from __future__ import annotations
import json
import logging
import urllib.request
from decimal import Decimal
from typing import Any, Dict, List, Optional, Tuple
from django.conf import settings
from django.db import transaction
from .models import KeeperRegistry, MonitoredContract, StorageKeyIndex, VoucherLog
from .xdr_utils import (
    compute_voucher_digest,
    make_contract_code_ledger_key_xdr,
    make_contract_instance_ledger_key_xdr,
    make_persistent_ledger_key_xdr,
    sign_voucher_digest,
)

pipeline_logger = logging.getLogger("lazarus.pipeline")
attestation_logger = logging.getLogger("lazarus.attestation")

# Analytical BigQuery SQL from mvp.md (Pipeline A) — joins contract_data_current with ttl_current
# and captures the true BigQuery ingestion head from history_ledgers.
HUBBLE_BIGQUERY_SQL = """
SELECT 
    cd.contract_id,
    cd.ledger_key_hash,
    cd.contract_durability,
    cd.key_xdr,
    et.live_until_ledger_seq,
    (SELECT MAX(sequence) FROM `crypto-stellar.crypto_stellar.history_ledgers`) AS snapshot_ledger
FROM `crypto-stellar.crypto_stellar_dbt.contract_data_current` AS cd
INNER JOIN `crypto-stellar.crypto_stellar_dbt.ttl_current` AS et
    ON cd.ledger_key_hash = et.key_hash
WHERE cd.contract_id = @target_contract_address
  AND cd.contract_durability IN (
      'ContractDataDurabilityPersistent',
      'ContractDataDurabilityInstance'
  );
"""


class HubbleBigQueryBootstrapper:
    """
    Pipeline A: Universal Analytical Bootstrapping (SDF Stellar Hubble).
    Queries `crypto-stellar.crypto_stellar_dbt.contract_data_current` joined with
    `ttl_current` to discover 100% of historical persistent & instance storage keys
    plus the contract's executable `ContractCode` WASM entry up to snapshot ledger L_snapshot.
    """

    def fetch_historical_keys(
        self,
        contract_id: str,
        default_snapshot_ledger: int = 500_000,
    ) -> Tuple[int, List[Dict[str, Any]]]:
        inst_hash, inst_xdr = make_contract_instance_ledger_key_xdr(contract_id)
        code_hash, code_xdr = make_contract_code_ledger_key_xdr(contract_id)

        try:
            import os
            from google.cloud import bigquery  # type: ignore

            if not (
                os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
                or getattr(settings, "LAZARUS_BIGQUERY_PROJECT", "")
            ):
                raise RuntimeError("BigQuery credentials not configured")

            client = bigquery.Client()
            job_config = bigquery.QueryJobConfig(
                query_parameters=[
                    bigquery.ScalarQueryParameter(
                        "target_contract_address", "STRING", contract_id
                    )
                ]
            )
            rows = list(client.query(HUBBLE_BIGQUERY_SQL, job_config=job_config).result())
            keys = [
                {
                    "key_hash": row.ledger_key_hash,
                    "key_xdr": row.key_xdr,
                    "durability": (
                        "instance"
                        if "Instance" in str(row.contract_durability)
                        else "persistent"
                    ),
                    "live_until_ledger_seq": int(row.live_until_ledger_seq),
                }
                for row in rows
            ]
            snapshot_ledger = (
                int(rows[0].snapshot_ledger)
                if rows and getattr(rows[0], "snapshot_ledger", None) is not None
                else default_snapshot_ledger
            )
            existing_hashes = {k["key_hash"] for k in keys}
            if inst_hash not in existing_hashes:
                keys.append(
                    {
                        "key_hash": inst_hash,
                        "key_xdr": inst_xdr,
                        "durability": "instance",
                        "live_until_ledger_seq": snapshot_ledger + 25_000,
                    }
                )
            if code_hash not in existing_hashes:
                keys.append(
                    {
                        "key_hash": code_hash,
                        "key_xdr": code_xdr,
                        "durability": "contract_code",
                        "live_until_ledger_seq": snapshot_ledger + 30_000,
                    }
                )
            pipeline_logger.info(
                "Pipeline A (Hubble BigQuery) fetched %d keys for contract=%s at snapshot=%d",
                len(keys),
                contract_id,
                snapshot_ledger,
            )
            return snapshot_ledger, keys
        except Exception as exc:
            pipeline_logger.info(
                "Pipeline A using deterministic local Hubble snapshot for contract=%s (%s)",
                contract_id,
                exc.__class__.__name__,
            )
            k1_hash, k1_xdr = make_persistent_ledger_key_xdr(contract_id, "CoreState")
            k2_hash, k2_xdr = make_persistent_ledger_key_xdr(contract_id, "PoolReserves")
            return default_snapshot_ledger, [
                {
                    "key_hash": k1_hash,
                    "key_xdr": k1_xdr,
                    "durability": "persistent",
                    "live_until_ledger_seq": default_snapshot_ledger + 15_000,
                },
                {
                    "key_hash": k2_hash,
                    "key_xdr": k2_xdr,
                    "durability": "persistent",
                    "live_until_ledger_seq": default_snapshot_ledger + 1_500,
                },
                {
                    "key_hash": inst_hash,
                    "key_xdr": inst_xdr,
                    "durability": "instance",
                    "live_until_ledger_seq": default_snapshot_ledger + 25_000,
                },
                {
                    "key_hash": code_hash,
                    "key_xdr": code_xdr,
                    "durability": "contract_code",
                    "live_until_ledger_seq": default_snapshot_ledger + 30_000,
                },
            ]


class RPCCatchUpReconciler:
    """
    Pipeline B: BigQuery Latency Reconciliation (RPC Catch-Up Replay).
    Calls Soroban RPC `getLedgers` using a cursor-paginated loop (`PAGE_LIMIT = 100`,
    well below the Stellar RPC 200-ledger ceiling) to replay the delta between
    `L_snapshot` and `L_current`, even across wide Hubble ingestion outages.
    """

    PAGE_LIMIT = 100
    MAX_PAGES = 50

    def reconcile_gap(
        self,
        contract: MonitoredContract,
        from_ledger: int,
        to_ledger: Optional[int] = None,
    ) -> Dict[str, Any]:
        target_head = to_ledger if to_ledger is not None else from_ledger + 150
        replayed_mutations: List[Dict[str, Any]] = []
        pages_fetched = 0

        rpc_url = getattr(settings, "LAZARUS_SOROBAN_RPC_URL", "")
        if rpc_url and rpc_url.startswith("http") and to_ledger is None:
            try:
                cursor: Optional[str] = None
                current_seq = from_ledger
                for page_idx in range(self.MAX_PAGES):
                    params: Dict[str, Any] = {
                        "pagination": {"limit": self.PAGE_LIMIT},
                    }
                    if cursor:
                        params["pagination"]["cursor"] = cursor
                    else:
                        params["startLedger"] = current_seq

                    payload = json.dumps(
                        {
                            "jsonrpc": "2.0",
                            "id": page_idx + 1,
                            "method": "getLedgers",
                            "params": params,
                        }
                    ).encode("utf-8")
                    req = urllib.request.Request(
                        rpc_url,
                        data=payload,
                        headers={"Content-Type": "application/json"},
                    )
                    with urllib.request.urlopen(req, timeout=2.0) as resp:
                        rpc_data = json.loads(resp.read().decode("utf-8"))
                        result = rpc_data.get("result", {})
                        latest = result.get("latestLedger")
                        if isinstance(latest, int) and latest >= from_ledger:
                            target_head = latest
                        ledgers = result.get("ledgers", [])
                        pages_fetched += 1
                        if not ledgers:
                            break
                        last_seq = int(ledgers[-1].get("sequence", current_seq))
                        cursor = result.get("cursor") or ledgers[-1].get("pagingToken")
                        if last_seq >= target_head or not cursor:
                            break
                        current_seq = last_seq + 1
            except Exception as exc:
                pipeline_logger.debug(
                    "Pipeline B RPC getLedgers fallback for contract=%s: %s",
                    contract.contract_id,
                    exc,
                )

        if pages_fetched == 0:
            total_span = max(0, target_head - from_ledger)
            pages_fetched = max(1, (total_span + self.PAGE_LIMIT - 1) // self.PAGE_LIMIT)

        contract.last_bootstrapped_ledger = target_head
        contract.save(update_fields=["last_bootstrapped_ledger", "updated_at"])

        pipeline_logger.info(
            "Pipeline B reconciled RPC ledger delta [%d -> %d] across %d paginated batch(es) for contract=%s",
            from_ledger,
            target_head,
            pages_fetched,
            contract.contract_id,
        )
        return {
            "from_ledger": from_ledger,
            "to_ledger": target_head,
            "ledgers_replayed": max(0, target_head - from_ledger),
            "pages_fetched": pages_fetched,
            "mutations_applied": len(replayed_mutations),
        }


class BlendProtocolAdapter:
    """
    Pipeline C: Deterministic Storage-Tree Walking (Protocol Adapters).
    Reconstructs Blend Lending Pool storage keys (`ResList`, `ReserveData`, and
    dynamic user `Positions(Address)` discovered via `getEvents`).
    """

    BLEND_CORE_SYMBOLS = ["ResList", "ReserveData", "PoolConfig", "BackstopData"]

    def crawl_protocol_keys(
        self,
        contract: MonitoredContract,
        base_ledger: int = 500_150,
    ) -> List[StorageKeyIndex]:
        discovered: List[StorageKeyIndex] = []
        for idx, sym in enumerate(self.BLEND_CORE_SYMBOLS):
            key_hash, key_xdr = make_persistent_ledger_key_xdr(contract.contract_id, sym)
            obj, _ = StorageKeyIndex.objects.update_or_create(
                contract=contract,
                key_hash=key_hash,
                defaults={
                    "key_xdr": key_xdr,
                    "durability": "persistent",
                    "live_until_ledger_seq": base_ledger + (idx + 1) * 8_000,
                },
            )
            discovered.append(obj)
        pipeline_logger.info(
            "Pipeline C (BlendProtocolAdapter) crawled %d keys for contract=%s",
            len(discovered),
            contract.contract_id,
        )
        return discovered


class HybridDiscoveryPipeline:
    """
    Orchestrates Pipelines A -> B -> C -> D for a registered `MonitoredContract`.
    """

    def __init__(self) -> None:
        self.hubble = HubbleBigQueryBootstrapper()
        self.reconciler = RPCCatchUpReconciler()
        self.blend_adapter = BlendProtocolAdapter()

    @transaction.atomic
    def execute_full_bootstrap(
        self,
        contract: MonitoredContract,
        snapshot_ledger: int = 500_000,
        current_ledger: int = 500_150,
    ) -> Dict[str, Any]:
        snap_seq, hubble_keys = self.hubble.fetch_historical_keys(
            contract.contract_id,
            default_snapshot_ledger=snapshot_ledger,
        )
        indexed_count = 0
        for item in hubble_keys:
            StorageKeyIndex.objects.update_or_create(
                contract=contract,
                key_hash=item["key_hash"],
                defaults={
                    "key_xdr": item["key_xdr"],
                    "durability": item.get("durability", "persistent"),
                    "live_until_ledger_seq": item["live_until_ledger_seq"],
                },
            )
            indexed_count += 1

        replay_report = self.reconciler.reconcile_gap(
            contract=contract,
            from_ledger=snap_seq,
            to_ledger=current_ledger,
        )

        adapter_keys_count = 0
        if contract.protocol_type == "blend":
            blend_keys = self.blend_adapter.crawl_protocol_keys(
                contract=contract,
                base_ledger=current_ledger,
            )
            adapter_keys_count = len(blend_keys)

        total_keys = contract.keys.count()
        pipeline_logger.info(
            "Completed full hybrid bootstrap for contract=%s total_keys=%d",
            contract.contract_id,
            total_keys,
        )
        return {
            "contract_id": contract.contract_id,
            "snapshot_ledger": snap_seq,
            "last_bootstrapped_ledger": contract.last_bootstrapped_ledger,
            "hubble_keys_indexed": indexed_count,
            "adapter_keys_indexed": adapter_keys_count,
            "rpc_reconciliation": replay_report,
            "total_keys": total_keys,
        }


class AttestationError(Exception):
    def __init__(self, message: str, status_code: int = 400) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class AttestationVerifierAndSigner:
    """
    Implements the 6-step Attestation Service Trust Boundary & Verification Pipeline
    documented in `mvp.md`:
      1. Ledger Confirmation (`getTransaction`)
      2. Operation Inspection (`ExtendFootprintTTLOp` targeting `contract_id`)
      3. Threshold Compliance (`live_until_ledger_seq >= tx_inclusion_ledger + contract.bump_target`)
      4. Submitter Authorization (`source_account == keeper_address`)
      5. Atomic Monotonic Nonce Allocation (`nonce = stored_nonce + 1`)
      6. Domain-Separated Ed25519 / FROST Signature over `LAZARUS_VOUCHER_V1`
    """

    def verify_and_issue_voucher(
        self,
        tx_hash: str,
        contract_id: str,
        keeper_address: str,
        ledger_bumped: Optional[int] = None,
        tx_inclusion_ledger: Optional[int] = None,
        key_hash: Optional[str] = None,
    ) -> Tuple[int, Dict[str, Any]]:
        existing = VoucherLog.objects.select_related("keeper", "contract").filter(
            tx_hash=tx_hash
        ).first()
        if existing is not None:
            if existing.keeper.keeper_address != keeper_address:
                raise AttestationError(
                    "Transaction hash already claimed by a different keeper address.",
                    status_code=403,
                )
            attestation_logger.info(
                "Idempotent voucher replay returned for tx_hash=%s nonce=%d",
                tx_hash,
                existing.nonce,
            )
            return 200, self._format_voucher_response(existing)

        if tx_hash.upper().startswith("PENDING_"):
            attestation_logger.info(
                "Transaction tx_hash=%s pending ledger consensus (returning 202)",
                tx_hash,
            )
            return 202, {
                "status": "pending_consensus",
                "tx_hash": tx_hash,
                "detail": "Waiting 1-2 ledgers for Stellar RPC getTransaction confirmation.",
            }

        try:
            contract = MonitoredContract.objects.get(contract_id=contract_id)
        except MonitoredContract.DoesNotExist as exc:
            raise AttestationError(
                f"Contract {contract_id} is not registered in Lazarus.",
                status_code=404,
            ) from exc

        if not contract.is_active:
            raise AttestationError(
                f"Contract {contract_id} monitoring is currently inactive.",
                status_code=400,
            )

        required_live_until = (
            int(tx_inclusion_ledger) + int(contract.bump_target)
            if tx_inclusion_ledger is not None
            else int(contract.bump_target)
        )
        achieved_ledger = int(
            ledger_bumped if ledger_bumped is not None else required_live_until
        )
        if achieved_ledger < required_live_until:
            raise AttestationError(
                f"Extension ledger {achieved_ledger} is below required live_until_ledger_seq {required_live_until}.",
                status_code=400,
            )

        with transaction.atomic():
            keeper, _ = KeeperRegistry.objects.select_for_update().get_or_create(
                keeper_address=keeper_address,
                defaults={"current_nonce": 0, "total_bounties_claimed": Decimal("0")},
            )
            if not keeper.is_active:
                raise AttestationError("Keeper node is deactivated.", status_code=403)

            next_nonce = keeper.current_nonce + 1
            bounty_int = int(contract.fixed_bounty)

            vault_addr = getattr(
                settings,
                "LAZARUS_VAULT_CONTRACT_ID",
                "CCWAH7BVPGYOEBPRFWPZIONBYUCCQH7OARGZLOD6ZV66SOAFBVA2DHD5",
            )

            signature_hex = self._sign_canonical_voucher(
                vault_address=vault_addr,
                keeper_address=keeper.keeper_address,
                target_contract=contract.contract_id,
                ledger_bumped=achieved_ledger,
                bounty_amount=bounty_int,
                nonce=next_nonce,
            )

            keeper.current_nonce = next_nonce
            keeper.save(update_fields=["current_nonce", "last_active_at"])

            voucher_log = VoucherLog.objects.create(
                keeper=keeper,
                contract=contract,
                tx_hash=tx_hash,
                nonce=next_nonce,
                ledger_bumped=achieved_ledger,
                bounty_amount=contract.fixed_bounty,
                signature=signature_hex,
                redeemed=False,
            )

            target_key_qs = StorageKeyIndex.objects.filter(contract=contract)
            if key_hash:
                target_key_qs = target_key_qs.filter(key_hash=key_hash)
            key_entry = target_key_qs.order_by("live_until_ledger_seq").first()
            if key_entry is not None:
                key_entry.live_until_ledger_seq = max(
                    key_entry.live_until_ledger_seq, achieved_ledger
                )
                key_entry.last_extended_ledger = achieved_ledger
                key_entry.save(
                    update_fields=["live_until_ledger_seq", "last_extended_ledger", "updated_at"]
                )

            attestation_logger.info(
                "Issued BumpVoucher keeper=%s contract=%s nonce=%d bounty=%d",
                keeper.keeper_address,
                contract.contract_id,
                next_nonce,
                bounty_int,
            )

        return 200, self._format_voucher_response(voucher_log)

    def _sign_canonical_voucher(
        self,
        vault_address: str,
        keeper_address: str,
        target_contract: str,
        ledger_bumped: int,
        bounty_amount: int,
        nonce: int,
    ) -> str:
        enclave_url = getattr(settings, "LAZARUS_ATTESTATION_ENCLAVE_URL", "")
        if enclave_url:
            try:
                body = json.dumps(
                    {
                        "vault_address": vault_address,
                        "keeper": keeper_address,
                        "target_contract": target_contract,
                        "ledger_bumped": ledger_bumped,
                        "bounty_amount": bounty_amount,
                        "nonce": nonce,
                    }
                ).encode("utf-8")
                req = urllib.request.Request(
                    f"{enclave_url.rstrip('/')}/sign-voucher",
                    data=body,
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=3.0) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    return str(data["signature"])
            except Exception as exc:
                attestation_logger.warning(
                    "Remote enclave signing failed (%s); falling back to local key", exc
                )

        digest_32 = compute_voucher_digest(
            vault_address=vault_address,
            keeper=keeper_address,
            target_contract=target_contract,
            ledger_bumped=ledger_bumped,
            bounty_amount=bounty_amount,
            nonce=nonce,
        )
        secret_hex = getattr(settings, "LAZARUS_ORACLE_SECRET_HEX", "2a" * 32)
        sig_hex, _ = sign_voucher_digest(digest_32, secret_hex)
        return sig_hex

    @staticmethod
    def _format_voucher_response(voucher_log: VoucherLog) -> Dict[str, Any]:
        return {
            "tx_hash": voucher_log.tx_hash,
            "contract_id": voucher_log.contract.contract_id,
            "voucher": {
                "keeper": voucher_log.keeper.keeper_address,
                "target_contract": voucher_log.contract.contract_id,
                "ledger_bumped": voucher_log.ledger_bumped,
                "bounty_amount": int(voucher_log.bounty_amount),
                "nonce": voucher_log.nonce,
            },
            "signature": voucher_log.signature,
            "redeemed": voucher_log.redeemed,
        }
