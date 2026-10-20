"""Move/Sui smart contract AST extraction using tree-sitter-move.

Provides full AST-based analysis for Move smart contracts (Sui, Aptos, etc.)
with parity to the Solidity extractor: function extraction, call graph,
state read/write tracking, access control detection (capability params),
and 21 vulnerability class detection.

If tree_sitter_move is not available (e.g. wrong platform wheel), falls back
to the regex-based MoveExtractor in core.web3.project_langs.
"""

import json
import re
import logging

logger = logging.getLogger(__name__)

from core.web3 import ExtractResult
from core.web3.base import BaseExtractor
from core.web3.project_langs import FunctionSpan

try:
    import tree_sitter_move
    from tree_sitter import Language, Parser
    _HAS_TREE_SITTER_MOVE = True
except ImportError:
    _HAS_TREE_SITTER_MOVE = False
    logger.warning(
        "tree_sitter_move not available (likely wrong platform wheel). "
        "Move extraction will fall back to regex-based extractor from "
        "core.web3.project_langs.MoveExtractor. "
        "For full AST-based analysis, install tree-sitter-move from source: "
        "git clone https://github.com/MystenLabs/sui && "
        "cd sui/external-crates/move/tooling/tree-sitter && "
        "cargo build --release"
    )

# Re-export the regex-based MoveExtractor as fallback when tree-sitter isn't available
if not _HAS_TREE_SITTER_MOVE:
    from core.web3.project_langs import MoveExtractor as _RegexMoveExtractor

MOVE_ACCESS_CONTROL_PATTERNS = (
    "&AdminCap", "&Publisher", "&TreasuryCap", "&FeeCollector",
    "&Coin<", "&Object", "&UID", "&Ticket<", "&Authenticator",
    "AdminCap", "Publisher", "TreasuryCap", "FeeCollector",
)

MOVE_ROLE_CHECK_FUNCS = (
    "check_pool_manager_role", "check_protocol_fee_claim_role",
    "check_rewarder_manager_role", "check_partner_manager_role",
    "check_emergency_pause_role", "check_emergency_unpause_role",
    "is_pool_manager", "is_allow_add_liquidity", "check_admin",
    "check_owner", "only_owner", "require_owner", "require_admin",
)

# 21 classes of vulnerability detection (parity with Solidity extractor)
MOVE_RISK_KEYWORDS = {
    "signature_risk": ("ecrecover", "sign", "verify", "recover"),
    "oracle_risk": ("price", "oracle", "price_feed", "spot_price", "twap"),
    "timestamp_dependence": ("timestamp_seconds", "timestamp_ms", "sui::clock"),
    "unsafe_downcast": ("u8(", "u16(", "u32(", "u64(", "u128(", "as u8", "as u16", "as u32", "as u64", "as u128"),
    "unchecked_arithmetic": ("unchecked",),
    "dos_risk": ("while", "loop", "for ", "vector::length"),
    "flash_loan_risk": ("flash_loan", "flash_swap", "flash_mint"),
    "erc_callback_risk": ("coin_receive", "on_receive", "tokensReceived", "onERC"),
    "unchecked_erc20": ("coin::transfer", "coin::transfer_signed", "balance::zero"),
    "precision_risk": (" / ", "div_"),
    "frontrun_risk": ("approve", "set_approval"),
    "reentrancy_risk": ("borrow_global_mut", "move_from", "move_to"),
    "cross_reentrancy": ("public_transfer", "transfer::transfer"),
    "proxy_risk": ("initialize", "__init", "upgrade", "set_implementation"),
}

class MoveExtractor(BaseExtractor):
    """Move/Sui smart contract extractor.

    Uses tree-sitter-move for AST-based analysis when available,
    otherwise falls back to regex-based extraction (same as Solidity-level
    detection but adapted for Move syntax).
    """

    language = "move"

    # Move capability types that function as access control (Move equivalent of onlyOwner/onlyRole)
    CAPABILITY_PARAMS = MOVE_ACCESS_CONTROL_PATTERNS

    # Role check function names used in Cetus and other Move projects
    MOVE_ROLE_CHECK_FUNCS = MOVE_ROLE_CHECK_FUNCS

    def __init__(self):
        self.parser = _get_parser() if _HAS_TREE_SITTER_MOVE else None
        self._struct_fields_by_name: dict[str, set[str]] = {}
        self._struct_fields_by_label: dict[str, set[str]] = {}
        self._struct_node_label: dict[str, str] = {}
        self._struct_node_file: dict[str, str] = {}
        self._fallback_extractor = None
        if not _HAS_TREE_SITTER_MOVE:
            self._fallback_extractor = _RegexMoveExtractor()

    def reset_struct_registry(self) -> None:
        """Clear the cross-file struct registry."""
        self._struct_fields_by_name = {}
        self._struct_fields_by_label = {}
        self._struct_node_label = {}
        self._struct_node_file = {}

    def prescan_file(self, source_code: bytes, file_path: str) -> None:
        """Register struct declarations in a file without emitting nodes."""
        if self.parser is not None:
            tree = self.parser.parse(source_code)
            self._prescan_structs(tree.root_node, file_path)
        elif self._fallback_extractor is not None:
            # Fallback extractor handles this via its own indexer flow
            pass

    def extract_from_source(self, source_code: bytes, file_path: str) -> ExtractResult:
        """Parse source and extract."""
        if self.parser is not None:
            tree = self.parser.parse(source_code)
            return self.extract(tree, source_code, file_path)
        elif self._fallback_extractor is not None:
            # Delegate to regex-based extractor
            return self._fallback_extractor.extract_from_source(source_code, file_path)
        return ExtractResult()

    def extract(self, tree, source_code: bytes, file_path: str) -> ExtractResult:
        """AST-based extraction (tree-sitter-move path)."""
        result = ExtractResult()
        root = tree.root_node

        self._prescan_structs(root, file_path)

        all_state_vars: set[str] = set()
        all_enums: dict[str, list[str]] = {}

        for child in root.children:
            if child.type == "module_declaration":
                self._extract_module(child, file_path, result, all_state_vars, all_enums)
            elif child.type == "struct_declaration":
                self._extract_struct(child, file_path, "", result)

        return result

    def _extract_module(self, node, file_path, result, all_state_vars, all_enums):
        """Extract a module declaration as a contract node."""
        name_node = _child_by_type(node, "identifier")
        if not name_node:
            return
        mod_name = _text(name_node)
        mod_id = self._make_node_id(file_path, mod_name)
        result.nodes.append({
            "id": mod_id, "label": mod_name, "type": "contract",
            "visibility": "public", "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": f"module {mod_name}",
            "metadata": json.dumps({"module": mod_name}),
        })

        body = _child_by_type(node, "module_body")
        container = body if body is not None else node

        for child in container.children:
            if child.type == "function_declaration":
                self._extract_function(child, file_path, mod_name, result, all_state_vars)
            elif child.type == "struct_declaration":
                self._extract_struct(child, file_path, mod_name, result)

    def _extract_struct(self, node, file_path, contract_name, result):
        """Extract struct declarations as nodes."""
        name_node = _child_by_type(node, "identifier")
        if not name_node:
            return
        struct_name = _text(name_node)
        if contract_name:
            qualified = f"{contract_name}.{struct_name}"
        else:
            qualified = struct_name
        struct_id = self._make_node_id(file_path, qualified)

        fields = []
        body = _child_by_type(node, "struct_body")
        container = body if body is not None else node
        for child in container.children:
            if child.type == "struct_field":
                type_n = _child_by_type(child, "type_annotation")
                name_n = _child_by_type(child, "identifier")
                fields.append({
                    "type": _text(type_n) if type_n else "",
                    "name": _text(name_n) if name_n else "",
                })

        meta = {"contract": contract_name} if contract_name else {}
        meta["fields"] = fields

        result.nodes.append({
            "id": struct_id, "label": struct_name, "type": "struct",
            "visibility": "public", "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": f"struct {struct_name}",
            "metadata": json.dumps(meta),
        })

        for f in fields:
            fname = f.get("name")
            if not fname:
                continue
            field_id = self._make_node_id(file_path, f"{qualified}.{fname}")
            field_meta = {
                "contract": contract_name,
                "struct": struct_name,
                "field": fname,
                "is_struct_field": True,
                "type_text": f.get("type", ""),
            }
            result.nodes.append({
                "id": field_id, "label": f"{struct_name}.{fname}", "type": "state_var",
                "visibility": "internal", "file": file_path,
                "line_start": node.start_point[0] + 1,
                "line_end": node.end_point[0] + 1,
                "signature": f.get("type", ""),
                "metadata": json.dumps(field_meta),
            })

    def _prescan_structs(self, root, file_path: str) -> None:
        """Collect all struct field names before extracting functions."""
        stack = [root]
        while stack:
            n = stack.pop()
            if n.type == "struct_declaration":
                name_node = _child_by_type(n, "identifier")
                if name_node:
                    sname = _text(name_node)
                    fields = set()
                    body = _child_by_type(n, "struct_body")
                    container = body if body is not None else n
                    for child in container.children:
                        if child.type == "struct_field":
                            name_n = _child_by_type(child, "identifier")
                            if name_n:
                                fields.add(_text(name_n))
                    cname = None
                    parent = n.parent
                    while parent is not None:
                        if parent.type in ("module_declaration",):
                            cn = _child_by_type(parent, "identifier")
                            cname = _text(cn) if cn else None
                            break
                        parent = parent.parent
                    label = f"{cname}.{sname}" if cname else sname
                    self._struct_fields_by_name.setdefault(sname, set()).update(fields)
                    self._struct_fields_by_label.setdefault(label, set()).update(fields)
                    self._struct_node_label[sname] = label
                    self._struct_node_label.setdefault(label, label)
                    self._struct_node_file[sname] = file_path
                    self._struct_node_file.setdefault(label, file_path)
            for c in n.children:
                stack.append(c)

    def _extract_function(self, node, file_path, contract_name, result, all_state_vars):
        """Extract a function declaration as a function node."""
        name_node = _child_by_type(node, "identifier")
        if not name_node:
            return
        func_name = _text(name_node)

        # Determine visibility
        vis = "private"
        has_entry = False
        has_public = False
        has_capability = False
        for child in node.children:
            if child.type == "public":
                has_public = True
                vis = "public"
            if child.type == "entry":
                has_entry = True
                vis = "external"

        # Check parameters for capability types
        sig_text = _text(node)
        has_capability = any(cap in sig_text for cap in MOVE_ACCESS_CONTROL_PATTERNS)

        if has_capability:
            vis += "+capability"

        # Check for role checks in body
        body_node = _child_by_type(node, "block")
        body_text = _text(body_node) if body_node else ""
        has_role_check = any(kw in body_text for kw in MOVE_ROLE_CHECK_FUNCS)

        sig = f"{func_name}({_extract_param_types(node)})"

        meta = super()._metadata(FunctionSpan(
            name=func_name, visibility=vis,
            start_line=node.start_point[0] + 1,
            end_line=node.end_point[0] + 1,
            signature=sig,
            body=body_text,
            scope=contract_name,
        ))

        # Move entry point
        if has_entry:
            meta["move_entry"] = True

        # Capability-based access control
        if has_capability or has_role_check:
            meta["capability_access_control"] = True
            meta["role_guards"] = sorted(set(meta.get("role_guards", [])) | {"capability_check"})

        # 21 CLASS DETECTIONS (parity with Solidity extractor)

        # 1. Signature replay (missing nonce/chain_id/domain separator)
        sig_risks = []
        if "ecrecover" in body_text or "recover" in body_text.lower() or "secp256k1" in body_text.lower():
            has_nonce = any(n in body_text.lower() for n in ("nonce", "nonces"))
            has_chain = ("chain_id" in body_text.lower() or "chainid" in body_text.lower())
            has_domain = ("DOMAIN_SEPARATOR" in body_text or "domainSeparator" in body_text or "_domainSeparator" in body_text or "eip712" in body_text.lower())
            if not has_nonce:
                sig_risks.append("missing_nonce")
            if not has_chain and not has_domain:
                sig_risks.append("missing_chain_id_or_domain")
            if sig_risks:
                meta["signature_risk"] = sig_risks

        # 2. Timestamp dependence (sui::clock::timestamp_seconds())
        ts_risks = []
        if "timestamp_seconds" in body_text or "timestamp_ms" in body_text or "sui::clock" in body_text:
            ts_comparisons = re.findall(
                r'(timestamp_seconds\s*(?:>=|<=|!=|==|>|<)\s*\w+|\w+\s*(?:>=|<=|!=|==|>|<)\s*timestamp_seconds)',
                body_text
            )
            ts_arithmetic = re.findall(
                r'(timestamp_seconds\s*[+\-*/]\s*\w+|\w+\s*[+\-*/]\s*timestamp_seconds)',
                body_text
            )
            for m in ts_comparisons + ts_arithmetic:
                ts_risks.append({"type": "timestamp_comparison", "expression": m.strip()})
            if ts_risks:
                meta["timestamp_dependence"] = ts_risks

        # 3. Unsafe downcasting (u8/u16/u32/u64/u128 narrowing)
        unsafe_casts = []
        for small in ("u8(", "u16(", "u32(", "u64(", "u128("):
            if small in body_text:
                unsafe_casts.append({"type": small.rstrip("("), "line": 0})
        if unsafe_casts:
            meta["unsafe_downcast"] = unsafe_casts

        # 4. Oracle / price manipulation spot reads
        oracle_risks = []
        if re.search(r"\b(balance::zero|coin::value|price|oracle|spot_price|twap)\b", body_text):
            if "price" in body_text.lower() or "oracle" in body_text.lower():
                oracle_risks.append({"type": "spot_price_read", "call": "price_oracle", "line": 0})
            if oracle_risks:
                meta["oracle_risk"] = oracle_risks

        # 5. DoS risks (unbounded loops, external calls in loops)
        dos_risks = []
        loops = re.findall(r"(?:while\s*\(|for\s*\(|loop\s*\{)", body_text)
        if loops:
            for lp in loops:
                dos_risks.append({"type": "unbounded_loop", "bound": "vector::length", "line": 0})
                break
        if re.search(r"\b(coin::transfer|public_transfer|transfer::transfer)\b", body_text) and loops:
            dos_risks.append({"type": "external_call_in_loop", "call": "coin_transfer", "line": 0})
        if dos_risks:
            meta["dos_risk"] = dos_risks

        # 6. Flash loan risk
        if re.search(r"\b(flash_loan|flash_swap|flash_mint)\b", body_text):
            meta["flash_loan_risk"] = ["flash_loan_entry"]

        # 7. ERC callback risk (coin receive callbacks)
        if re.search(r"\b(coin_receive|on_receive|tokensReceived|onERC)\b", body_text, re.IGNORECASE):
            meta["erc_callback_risk"] = ["coin_receive_entry"]

        # 8. Unchecked ERC20 equivalent (coin transfer without return value check)
        if re.search(r"\bcoin::transfer\b", body_text) and not re.search(r"\b(assert!|abort!|if\s*\(.*!)\s*", body_text):
            meta["unchecked_erc20"] = [{"target": "coin::transfer", "line": 0}]

        # 9. Precision risk (division before multiplication)
        if re.search(r"/\s*\w+\s*\*", body_text):
            meta["precision_risk"] = [{"type": "division_before_multiplication", "expression": "/ * pattern", "line": 0}]

        # 10. Frontrun risk (approve without zero-set)
        if re.search(r"\bapprove\b", body_text) and "approve(0" not in body_text and "forceApprove" not in body_text:
            meta["frontrun_risk"] = [{"type": "approve_race", "target": "approve", "line": 0}]

        # 11. tx.origin equivalent (tx_context::sender without validation)
        if "tx_context::sender(ctx)" in body_text and "check_" not in body_text and "assert!" not in body_text and "abort!" not in body_text:
            meta["tx_origin"] = True

        # 12. Proxy/upgrade risk (init without initializer)
        if func_name in ("init", "__init") and "initializer" not in body_text and "onlyInitializing" not in body_text:
            meta["proxy_risk"] = ["initialize_without_initializer_modifier"]
        if "upgrade" in body_text.lower() or "set_implementation" in body_text:
            meta["proxy_risk"] = meta.get("proxy_risk", []) + ["contains_upgrade_logic"]

        # 13. Privileged operations / unguarded privileged
        privileged_ops = []
        if re.search(r"\b(upgrade|implementation_change|delegate_execution|shutdown|pause|unpause)\b", body_text):
            privileged_ops.append("upgrade_surface")
        if vis.split("+")[0] in ("external", "public") and not has_capability and not has_role_check:
            meta["unguarded_privileged_operation"] = True
        if privileged_ops:
            meta["privileged_operations"] = privileged_ops
            if any(op in ("upgrade", "implementation_change", "delegate_execution", "shutdown") for op in privileged_ops):
                meta["upgrade_surface"] = True

        # 14. Reentrancy risk (Move borrow_global_mut/move_from/move_to)
        if re.search(r"\b(borrow_global_mut|move_from|move_to)\b", body_text):
            meta["reentrancy_risk"] = ["global_mut_access"]
        if re.search(r"\b(public_transfer|transfer::transfer)\b", body_text):
            meta["cross_reentrancy"] = ["public_transfer"]

        # 15. No input validation (external/public state-changing without assert/abort/if)
        if vis.split("+")[0] in ("external", "public") and not has_capability and not has_role_check:
            has_params = bool(_child_by_type(node, "parameters")) and func_name not in ("init",)
            validation_kw = ("assert!", "abort!", "if (", "assert_eq!", "debug_assert!")
            has_validation = any(kw in body_text for kw in validation_kw)
            if has_params and not has_validation:
                meta["no_input_validation"] = True

        # --- Move-specific additional detections ---

        # 16. Public transfer without sender authorization check
        if re.search(r"\b(transfer::public_transfer|transfer::transfer)\b", body_text):
            if not re.search(r"\bcheck_\w+_role\b|\bassert!\b.*\bsender\b|\bassert!\b.*\bowner\b", body_text):
                meta["unauthorized_transfer"] = ["public_transfer_without_auth_check"]

        # 17. Unsafe share object
        if "public_share_object" in body_text and "check_" not in body_text and "assert!" not in body_text:
            meta["unsafe_share_object"] = ["share_object_without_auth_check"]

        # 18. Unauthorized object creation
        if "object::new(ctx)" in body_text and vis.split("+")[0] in ("external", "public"):
            if not has_capability and not has_role_check:
                meta["unauthorized_object_creation"] = ["object_new_without_auth"]

        # 19. Unsafe package upgrade
        if "package::upgrade" in body_text or "package::publish" in body_text:
            if "check_" not in body_text and "assert!" not in body_text:
                meta["unsafe_package_upgrade"] = ["package_upgrade_without_auth"]

        # 20. Unprotected flash loan
        if re.search(r"\b(flash_loan|flash_swap)\b", body_text):
            if "nonReentrant" not in body_text and "reentrancy_guard" not in body_text and "check_" not in body_text:
                meta["unprotected_flash_loan"] = ["flash_loan_without_reentrancy_guard"]

        # 21. Missing event emission on state-changing operations
        if vis.split("+")[0] in ("external", "public") and not has_capability and not has_role_check:
            state_changing = re.search(r"\b(coin::transfer|public_transfer|move_to|move_from|borrow_global_mut)\b", body_text)
            has_event = "event::emit" in body_text
            if state_changing and not has_event:
                meta["missing_event_emission"] = ["state_change_without_event"]

        result.nodes.append({
            "id": self._make_node_id(file_path, f"{contract_name}.{func_name}"),
            "label": func_name, "type": "function",
            "visibility": vis, "file": file_path,
            "line_start": node.start_point[0] + 1,
            "line_end": node.end_point[0] + 1,
            "signature": sig,
            "metadata": json.dumps(meta),
        })

        # Call edges
        for call in _collect_calls(body_node):
            call_name = _get_call_name(call)
            full_target = _extract_call_target_full(call)
            if call_name and call_name not in ("assert!", "abort!"):
                target_id = self._make_node_id(file_path, f"{contract_name}.{call_name}")
                result.edges.append({
                    "source": self._make_node_id(file_path, f"{contract_name}.{func_name}"),
                    "target": target_id,
                    "relation": "calls",
                    "attributes": json.dumps({"call_name": call_name}),
                })

        # State write edges
        for assign in _collect_assignments(body_node):
            lhs_ids = _collect_identifiers(assign)
            written_vars = lhs_ids & all_state_vars
            for var_name in written_vars:
                var_id = self._make_node_id(file_path, f"{contract_name}.{var_name}")
                result.edges.append({
                    "source": self._make_node_id(file_path, f"{contract_name}.{func_name}"),
                    "target": var_id,
                    "relation": "writes_state",
                    "attributes": "{}",
                })

        # State read edges
        for ident in _collect_identifiers(body_node):
            if ident in all_state_vars:
                var_id = self._make_node_id(file_path, f"{contract_name}.{ident}")
                result.edges.append({
                    "source": self._make_node_id(file_path, f"{contract_name}.{func_name}"),
                    "target": var_id,
                    "relation": "reads_state",
                    "attributes": "{}",
                })

    def _state_writes(self, span: FunctionSpan) -> list[str]:
        names = re.findall(r"\b(?:move_to|move_from|borrow_global_mut)\s*<\s*([^>]+)>", span.body)
        if "transfer::" in span.body or "public_transfer" in span.body:
            names.append("asset_transfer")
        if re.search(r"\bcoin::transfer\b", span.body):
            names.append("coin_transfer")
        if re.search(r"\bbalance::\w+", span.body):
            names.append("balance_write")
        return names

    def _state_reads(self, span: FunctionSpan) -> list[str]:
        return re.findall(r"\b(?:borrow_global|exists)\s*<\s*([^>]+)>", span.body)

    def _metadata(self, span: FunctionSpan) -> dict:
        meta = super()._metadata(span)
        body = span.body
        sig = span.signature

        # --- Move entry point (public/entry fun) ---
        if re.search(r"\b(entry\s+fun|public\s+entry\s+fun)", span.signature):
            meta["move_entry"] = True

        # --- Capability-based access control (Move equivalent of onlyOwner) ---
        has_capability = any(cap in sig for cap in MOVE_ACCESS_CONTROL_PATTERNS)
        has_role_check = any(kw in body for kw in MOVE_ROLE_CHECK_FUNCS)
        if has_capability or has_role_check:
            meta["capability_access_control"] = True
            meta["role_guards"] = sorted(set(meta.get("role_guards", [])) | {"capability_check"})

        # --- Move entry (external) ---
        if "transfer::" in span.body or "public_transfer" in span.body:
            meta["cross_contract_calls"] = ["transfer_module"]

        # --- 21 CLASS DETECTIONS (parity with Solidity extractor) ---

        # 1. Signature replay (missing nonce/chain_id/domain separator)
        sig_risks = []
        if "ecrecover" in body or "recover" in body.lower() or "secp256k1" in body.lower():
            has_nonce = any(n in body.lower() for n in ("nonce", "nonces"))
            has_chain = ("chain_id" in body.lower() or "chainid" in body.lower())
            has_domain = ("DOMAIN_SEPARATOR" in body or "domainSeparator" in body or "_domainSeparator" in body or "eip712" in body.lower())
            if not has_nonce:
                sig_risks.append("missing_nonce")
            if not has_chain and not has_domain:
                sig_risks.append("missing_chain_id_or_domain")
            if sig_risks:
                meta["signature_risk"] = sig_risks

        # 2. Timestamp dependence (sui::clock::timestamp_seconds())
        ts_risks = []
        if "timestamp_seconds" in body or "timestamp_ms" in body or "sui::clock" in body:
            ts_comparisons = re.findall(
                r'(timestamp_seconds\s*(?:>=|<=|!=|==|>|<)\s*\w+|\w+\s*(?:>=|<=|!=|==|>|<)\s*timestamp_seconds)',
                body
            )
            ts_arithmetic = re.findall(
                r'(timestamp_seconds\s*[+\-*/]\s*\w+|\w+\s*[+\-*/]\s*timestamp_seconds)',
                body
            )
            for m in ts_comparisons + ts_arithmetic:
                ts_risks.append({"type": "timestamp_comparison", "expression": m.strip()})
            if ts_risks:
                meta["timestamp_dependence"] = ts_risks

        # 3. Unsafe downcasting (u8/u16/u32/u64/u128 narrowing)
        unsafe_casts = []
        for small in ("u8(", "u16(", "u32(", "u64(", "u128("):
            if small in body:
                unsafe_casts.append({"type": small.rstrip("("), "line": 0})
        if unsafe_casts:
            meta["unsafe_downcast"] = unsafe_casts

        # 4. Oracle / price manipulation spot reads
        oracle_risks = []
        if re.search(r"\b(balance::zero|coin::value|price|oracle|spot_price|twap)\b", body):
            if "price" in body.lower() or "oracle" in body.lower():
                oracle_risks.append({"type": "spot_price_read", "call": "price_oracle", "line": 0})
            if oracle_risks:
                meta["oracle_risk"] = oracle_risks

        # 5. DoS risks (unbounded loops, external calls in loops)
        dos_risks = []
        loops = re.findall(r"(?:while\s*\(|for\s*\(|loop\s*\{)", body)
        if loops:
            for lp in loops:
                dos_risks.append({"type": "unbounded_loop", "bound": "vector::length", "line": 0})
                break
        if re.search(r"\b(coin::transfer|public_transfer|transfer::transfer)\b", body) and loops:
            dos_risks.append({"type": "external_call_in_loop", "call": "coin_transfer", "line": 0})
        if dos_risks:
            meta["dos_risk"] = dos_risks

        # 6. Flash loan risk
        if re.search(r"\b(flash_loan|flash_swap|flash_mint)\b", body):
            meta["flash_loan_risk"] = ["flash_loan_entry"]

        # 7. ERC callback risk (coin receive callbacks)
        if re.search(r"\b(coin_receive|on_receive|tokensReceived|onERC)\b", body, re.IGNORECASE):
            meta["erc_callback_risk"] = ["coin_receive_entry"]

        # 8. Unchecked ERC20 equivalent (coin transfer without return value check)
        if re.search(r"\bcoin::transfer\b", span.body) and not re.search(r"\b(assert!|abort!|if\s*\(.*!)\s*", span.body):
            meta["unchecked_erc20"] = [{"target": "coin::transfer", "line": 0}]

        # 9. Precision risk (division before multiplication)
        if re.search(r"/\s*\w+\s*\*", body):
            meta["precision_risk"] = [{"type": "division_before_multiplication", "expression": "/ * pattern", "line": 0}]

        # 10. Frontrun risk (approve without zero-set)
        if re.search(r"\bapprove\b", body) and "approve(0" not in body and "forceApprove" not in body:
            meta["frontrun_risk"] = [{"type": "approve_race", "target": "approve", "line": 0}]

        # 11. tx.origin equivalent (tx_context::sender without validation)
        if "tx_context::sender(ctx)" in body and "check_" not in body and "assert!" not in body and "abort!" not in body:
            meta["tx_origin"] = True

        # 12. Proxy/upgrade risk (init without initializer)
        if span.name in ("init", "__init") and "initializer" not in body and "onlyInitializing" not in body:
            meta["proxy_risk"] = ["initialize_without_initializer_modifier"]
        if "upgrade" in body.lower() or "set_implementation" in body:
            meta["proxy_risk"] = meta.get("proxy_risk", []) + ["contains_upgrade_logic"]

        # 13. Privileged operations / unguarded privileged
        privileged_ops = []
        if re.search(r"\b(upgrade|implementation_change|delegate_execution|shutdown|pause|unpause)\b", body):
            privileged_ops.append("upgrade_surface")
        if span.visibility in ("external", "public") and not has_capability and not has_role_check:
            meta["unguarded_privileged_operation"] = True
        if privileged_ops:
            meta["privileged_operations"] = privileged_ops
            if any(op in ("upgrade", "implementation_change", "delegate_execution", "shutdown") for op in privileged_ops):
                meta["upgrade_surface"] = True

        # 14. Reentrancy risk (Move borrow_global_mut/move_from/move_to)
        if re.search(r"\b(borrow_global_mut|move_from|move_to)\b", body):
            meta["reentrancy_risk"] = ["global_mut_access"]
        if re.search(r"\b(public_transfer|transfer::transfer)\b", body):
            meta["cross_reentrancy"] = ["public_transfer"]

        # 15. No input validation (external/public state-changing without assert/abort/if)
        if span.visibility in ("external", "public") and not has_capability and not has_role_check:
            # Check if function has parameters (has params beyond ctx)
            has_params = bool(re.search(r"\)\s*\{", body)) and span.name not in ("init",)
            validation_kw = ("assert!", "abort!", "if (", "assert_eq!", "debug_assert!")
            has_validation = any(kw in body for kw in validation_kw)
            if has_params and not has_validation:
                meta["no_input_validation"] = True

        # --- Move-specific additional detections ---

        # 16. Public transfer without sender authorization check
        if re.search(r"\b(transfer::public_transfer|transfer::transfer)\b", body):
            if not re.search(r"\bcheck_\w+_role\b|\bassert!\b.*\bsender\b|\bassert!\b.*\bowner\b", body):
                meta["unauthorized_transfer"] = ["public_transfer_without_auth_check"]

        # 17. Unsafe share object
        if "public_share_object" in body and "check_" not in body and "assert!" not in body:
            meta["unsafe_share_object"] = ["share_object_without_auth_check"]

        # 18. Unauthorized object creation
        if "object::new(ctx)" in body and span.visibility in ("external", "public"):
            if not has_capability and not has_role_check:
                meta["unauthorized_object_creation"] = ["object_new_without_auth"]

        # 19. Unsafe package upgrade
        if "package::upgrade" in body or "package::publish" in body:
            if "check_" not in body and "assert!" not in body:
                meta["unsafe_package_upgrade"] = ["package_upgrade_without_auth"]

        # 20. Unprotected flash loan
        if re.search(r"\b(flash_loan|flash_swap)\b", body):
            if "nonReentrant" not in body and "reentrancy_guard" not in body and "check_" not in body:
                meta["unprotected_flash_loan"] = ["flash_loan_without_reentrancy_guard"]

        # 21. Missing event emission on state-changing operations
        if span.visibility in ("external", "public") and not has_capability and not has_role_check:
            state_changing = re.search(r"\b(coin::transfer|public_transfer|move_to|move_from|borrow_global_mut)\b", body)
            has_event = "event::emit" in body
            if state_changing and not has_event:
                meta["missing_event_emission"] = ["state_change_without_event"]

        return meta
