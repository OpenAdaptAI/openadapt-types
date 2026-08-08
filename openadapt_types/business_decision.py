"""Portable, privacy-safe contracts for finite business decisions.

This family is separate from :mod:`openadapt_types.human_decision`.
``HumanDecisionTaskV2`` resolves an operational runtime halt.  A
``BusinessDecisionTaskV1`` presents one finite branch that was declared and
qualified before the run started.  It never grants Continue, Skip, Teach, or
Reconcile authority.

The portable task is a presentation and authentication projection.  It is not
execution authority.  The customer runner must authenticate the task, submit
the selected option through Flow's business-decision store, reacquire the live
application state, and pass the successor action's normal identity and effect
contracts before it actuates.

No question text, option label, screenshot, OCR output, record value, or live
identifier belongs in this wire format.  A consumer renders reviewed static
copy from the exact ``presentation_digest``.  A decision that needs protected
context is ``local_answer_required`` and cannot be answered by a remote client.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from datetime import datetime
from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    model_validator,
)

BUSINESS_DECISION_TASK_SCHEMA = "openadapt.business-decision-task/v1"
BUSINESS_DECISION_ANSWER_SCHEMA = "openadapt.business-decision-answer/v1"
BUSINESS_DECISION_PRESENTATION_SCHEMA = "openadapt.business-decision-presentation/v1"
BUSINESS_DECISION_DELIVERY_POLICY_SCHEMA = (
    "openadapt.business-decision-delivery-policy/v1"
)
BUSINESS_DECISION_ANSWER_RECEIPT_SCHEMA = "openadapt.business-decision-answer-receipt/v1"

_TASK_DOMAIN = b"openadapt.business-decision-task/v1\x00"
_ANSWER_DOMAIN = b"openadapt.business-decision-answer/v1\x00"
_DELIVERY_POLICY_DOMAIN = b"openadapt.business-decision-delivery-policy/v1\x00"
_ANSWER_RECEIPT_DOMAIN = b"openadapt.business-decision-answer-receipt/v1\x00"
_OPAQUE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$"
_OPTION_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
_IDEMPOTENCY_KEY_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{15,199}$"
_SHA256_PATTERN = r"^sha256:[0-9a-f]{64}$"
_SIGNATURE_PATTERN = r"^hmac-sha256:[0-9a-f]{64}$"
_ROLE_MAPPING_DIGEST_PATTERN = _SIGNATURE_PATTERN
_TIMESTAMP_PATTERN = (
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?(Z|[+-]\d{2}:\d{2})$"
)
_OpaqueRoleRef = Annotated[StrictStr, Field(pattern=_OPAQUE_ID_PATTERN)]
_STATIC_PRESENTATION_TEXT_PATTERN = r"^[^\x00-\x1f\x7f]{1,500}$"


class _StrictContract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class BusinessDecisionDeliveryMode(str, Enum):
    """Whether the decision can leave the customer-controlled context."""

    REMOTE_ANSWERABLE = "remote_answerable"
    LOCAL_ANSWER_REQUIRED = "local_answer_required"


class BusinessDecisionRequiredAuthn(str, Enum):
    """The exact authentication profile required by the qualified contract."""

    LOCAL_ENTERPRISE_IDENTITY = "local_enterprise_identity"
    AAL2 = "aal2"
    WEBAUTHN = "webauthn"


class BusinessDecisionOptionBindingV1(_StrictContract):
    """One finite option and its opaque compiled-successor commitment."""

    option_id: StrictStr = Field(pattern=_OPTION_ID_PATTERN)
    target_binding_digest: StrictStr = Field(pattern=_SHA256_PATTERN)


class BusinessDecisionPresentationOptionV1(_StrictContract):
    """One exact option label from the reviewed workflow contract."""

    option_id: StrictStr = Field(pattern=_OPTION_ID_PATTERN)
    label: StrictStr = Field(
        min_length=1,
        max_length=120,
        pattern=_STATIC_PRESENTATION_TEXT_PATTERN,
    )


class BusinessDecisionPresentationV1(_StrictContract):
    """Reviewed static copy for one exact qualified business decision.

    This artifact is separate from the Cloud-safe task because it contains
    human-readable text. The qualification path must review it before remote
    use. The signed task carries only this artifact's digest and opaque ref.
    """

    schema_version: Literal["openadapt.business-decision-presentation/v1"] = (
        BUSINESS_DECISION_PRESENTATION_SCHEMA
    )
    presentation_ref: StrictStr = Field(pattern=_OPAQUE_ID_PATTERN)
    presentation_revision: StrictInt = Field(ge=1, le=2_147_483_647)
    decision_contract_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    decision_contract_revision: StrictInt = Field(ge=1, le=2_147_483_647)
    question: StrictStr = Field(
        min_length=1,
        max_length=500,
        pattern=_STATIC_PRESENTATION_TEXT_PATTERN,
    )
    options: tuple[BusinessDecisionPresentationOptionV1, ...] = Field(
        min_length=2,
        max_length=32,
    )
    review_contract_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    reviewed_safe_for_remote: Literal[True] = True

    @model_validator(mode="after")
    def _validate_presentation(self) -> BusinessDecisionPresentationV1:
        if self.question.strip() != self.question:
            raise ValueError("business decision question must be trimmed")
        option_ids = tuple(option.option_id for option in self.options)
        labels = tuple(option.label for option in self.options)
        if len(option_ids) != len(set(option_ids)):
            raise ValueError("business decision presentation option ids must be unique")
        if any(label.strip() != label for label in labels):
            raise ValueError("business decision presentation labels must be trimmed")
        if len({label.casefold() for label in labels}) != len(labels):
            raise ValueError("business decision presentation labels must be unique")
        return self

    def canonical_bytes(self) -> bytes:
        return _canonical_json(self.model_dump(mode="json"))

    @property
    def digest(self) -> str:
        return _digest(self.canonical_bytes())


class BusinessDecisionDeliveryPolicyV1(_StrictContract):
    """Signed qualification policy for local or remote decision delivery."""

    schema_version: Literal[
        "openadapt.business-decision-delivery-policy/v1"
    ] = BUSINESS_DECISION_DELIVERY_POLICY_SCHEMA
    policy_ref: StrictStr = Field(pattern=_OPAQUE_ID_PATTERN)
    policy_revision: StrictInt = Field(ge=1, le=2_147_483_647)
    decision_contract_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    decision_contract_revision: StrictInt = Field(ge=1, le=2_147_483_647)
    presentation_ref: StrictStr = Field(pattern=_OPAQUE_ID_PATTERN)
    presentation_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    authorized_role_refs: tuple[_OpaqueRoleRef, ...] = Field(
        min_length=1, max_length=16
    )
    authorized_route_refs: tuple[_OpaqueRoleRef, ...] = Field(
        min_length=1, max_length=16
    )
    authorized_answer_issuer_key_ids: tuple[_OpaqueRoleRef, ...] = Field(
        min_length=1, max_length=16
    )
    role_mapping_digest: StrictStr = Field(pattern=_ROLE_MAPPING_DIGEST_PATTERN)
    required_authn: BusinessDecisionRequiredAuthn
    delivery_mode: BusinessDecisionDeliveryMode
    relay_capability_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    created_at: StrictStr = Field(
        min_length=20, max_length=40, pattern=_TIMESTAMP_PATTERN
    )
    expires_at: StrictStr = Field(
        min_length=20, max_length=40, pattern=_TIMESTAMP_PATTERN
    )
    issuer_key_id: StrictStr = Field(pattern=_OPAQUE_ID_PATTERN)
    signature_algorithm: Literal["hmac-sha256"] = "hmac-sha256"
    signature: StrictStr = Field(pattern=_SIGNATURE_PATTERN)

    @model_validator(mode="after")
    def _validate_policy(self) -> BusinessDecisionDeliveryPolicyV1:
        if len(self.authorized_role_refs) != len(set(self.authorized_role_refs)):
            raise ValueError("business decision policy role refs must be unique")
        if len(self.authorized_route_refs) != len(set(self.authorized_route_refs)):
            raise ValueError("business decision policy route refs must be unique")
        if len(self.authorized_answer_issuer_key_ids) != len(
            set(self.authorized_answer_issuer_key_ids)
        ):
            raise ValueError("business decision policy answer key ids must be unique")
        if _parse_timestamp(self.expires_at, "expires_at") <= _parse_timestamp(
            self.created_at, "created_at"
        ):
            raise ValueError("expires_at must be after created_at")
        return self

    def unsigned_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"signature"})

    def canonical_unsigned_bytes(self) -> bytes:
        return _canonical_json(self.unsigned_payload())

    @property
    def digest(self) -> str:
        return _digest(self.canonical_unsigned_bytes())

    def verify_hmac(self, key: bytes) -> bool:
        return _verify_hmac(
            key,
            self.unsigned_payload(),
            self.signature,
            _DELIVERY_POLICY_DOMAIN,
        )


class BusinessDecisionTaskV1(_StrictContract):
    """A signed remote-safe projection of one exact business-decision pause."""

    schema_version: Literal["openadapt.business-decision-task/v1"] = (
        BUSINESS_DECISION_TASK_SCHEMA
    )
    task_id: StrictStr = Field(pattern=_OPAQUE_ID_PATTERN)
    task_revision: StrictInt = Field(default=1, ge=1, le=2_147_483_647)
    tenant_id: StrictStr = Field(pattern=_OPAQUE_ID_PATTERN)
    runner_id: StrictStr = Field(pattern=_OPAQUE_ID_PATTERN)
    run_id: StrictStr = Field(pattern=_OPAQUE_ID_PATTERN)
    pause_id: StrictStr = Field(pattern=_OPAQUE_ID_PATTERN)
    pause_binding_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    request_id: StrictStr = Field(pattern=_OPAQUE_ID_PATTERN)
    request_revision: StrictInt = Field(default=1, ge=1, le=2_147_483_647)
    request_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    supersedes_request_digest: StrictStr | None = Field(
        default=None, pattern=_SHA256_PATTERN
    )
    bundle_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    workflow_contract_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    governed_runtime_inputs_digest: StrictStr | None = Field(
        default=None, pattern=_SHA256_PATTERN
    )
    decision_contract_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    decision_contract_revision: StrictInt = Field(ge=1, le=2_147_483_647)
    delivery_policy_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    program_scope_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    control_frames_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    presentation_ref: StrictStr = Field(pattern=_OPAQUE_ID_PATTERN)
    presentation_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    options: tuple[BusinessDecisionOptionBindingV1, ...] = Field(
        min_length=2,
        max_length=32,
    )
    authorized_role_refs: tuple[_OpaqueRoleRef, ...] = Field(
        min_length=1, max_length=16
    )
    authorized_route_refs: tuple[_OpaqueRoleRef, ...] = Field(
        min_length=1, max_length=16
    )
    authorized_answer_issuer_key_ids: tuple[_OpaqueRoleRef, ...] = Field(
        min_length=1, max_length=16
    )
    role_mapping_digest: StrictStr = Field(pattern=_ROLE_MAPPING_DIGEST_PATTERN)
    required_authn: BusinessDecisionRequiredAuthn
    delivery_mode: BusinessDecisionDeliveryMode
    local_evidence_required: StrictBool
    required_evidence_count: StrictInt = Field(default=0, ge=0, le=64)
    relay_capability_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    idempotency_scope_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    created_at: StrictStr = Field(
        min_length=20, max_length=40, pattern=_TIMESTAMP_PATTERN
    )
    expires_at: StrictStr = Field(
        min_length=20, max_length=40, pattern=_TIMESTAMP_PATTERN
    )
    issuer_key_id: StrictStr = Field(pattern=_OPAQUE_ID_PATTERN)
    signature_algorithm: Literal["hmac-sha256"] = "hmac-sha256"
    signature: StrictStr = Field(pattern=_SIGNATURE_PATTERN)

    @model_validator(mode="after")
    def _validate_task(self) -> BusinessDecisionTaskV1:
        option_ids = tuple(option.option_id for option in self.options)
        if len(option_ids) != len(set(option_ids)):
            raise ValueError("business decision option ids must be unique")
        if len(self.authorized_role_refs) != len(set(self.authorized_role_refs)):
            raise ValueError("business decision role refs must be unique")
        if len(self.authorized_route_refs) != len(set(self.authorized_route_refs)):
            raise ValueError("business decision route refs must be unique")
        if len(self.authorized_answer_issuer_key_ids) != len(
            set(self.authorized_answer_issuer_key_ids)
        ):
            raise ValueError("business decision answer key ids must be unique")
        created_at = _parse_timestamp(self.created_at, "created_at")
        expires_at = _parse_timestamp(self.expires_at, "expires_at")
        if expires_at <= created_at:
            raise ValueError("expires_at must be after created_at")
        if self.required_evidence_count > 0 and not self.local_evidence_required:
            raise ValueError(
                "required evidence count requires local_evidence_required=true"
            )
        if (
            self.delivery_mode is BusinessDecisionDeliveryMode.REMOTE_ANSWERABLE
            and self.local_evidence_required
        ):
            raise ValueError(
                "a remote-answerable decision cannot require protected local evidence"
            )
        if self.request_revision == 1 and self.supersedes_request_digest is not None:
            raise ValueError("the first request revision cannot supersede a request")
        if self.request_revision > 1 and self.supersedes_request_digest is None:
            raise ValueError("a renewed request must bind its predecessor")
        return self

    def unsigned_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"signature"})

    def canonical_unsigned_bytes(self) -> bytes:
        return _canonical_json(self.unsigned_payload())

    @property
    def digest(self) -> str:
        return _digest(self.canonical_unsigned_bytes())

    def verify_hmac(self, key: bytes) -> bool:
        return _verify_hmac(key, self.unsigned_payload(), self.signature, _TASK_DOMAIN)


class BusinessDecisionAnswerV1(_StrictContract):
    """An authenticated route's signed relay of one finite mobile answer.

    The client chooses only ``option_id`` and supplies one idempotency key.  The
    authenticated route, not the client, must populate the principal, role, and
    authentication-context references before it signs this contract.
    """

    schema_version: Literal["openadapt.business-decision-answer/v1"] = (
        BUSINESS_DECISION_ANSWER_SCHEMA
    )
    task_id: StrictStr = Field(pattern=_OPAQUE_ID_PATTERN)
    task_revision: StrictInt = Field(ge=1, le=2_147_483_647)
    task_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    request_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    option_id: StrictStr = Field(pattern=_OPTION_ID_PATTERN)
    idempotency_key: StrictStr = Field(pattern=_IDEMPOTENCY_KEY_PATTERN)
    authenticated_principal_ref: StrictStr = Field(pattern=_OPAQUE_ID_PATTERN)
    authenticated_role_ref: StrictStr = Field(pattern=_OPAQUE_ID_PATTERN)
    authn_assurance: BusinessDecisionRequiredAuthn
    authenticated_route_ref: StrictStr = Field(pattern=_OPAQUE_ID_PATTERN)
    role_mapping_digest: StrictStr = Field(pattern=_ROLE_MAPPING_DIGEST_PATTERN)
    authentication_context_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    answered_at: StrictStr = Field(
        min_length=20, max_length=40, pattern=_TIMESTAMP_PATTERN
    )
    issuer_key_id: StrictStr = Field(pattern=_OPAQUE_ID_PATTERN)
    signature_algorithm: Literal["hmac-sha256"] = "hmac-sha256"
    signature: StrictStr = Field(pattern=_SIGNATURE_PATTERN)

    @model_validator(mode="after")
    def _validate_answered_at(self) -> BusinessDecisionAnswerV1:
        _parse_timestamp(self.answered_at, "answered_at")
        return self

    def unsigned_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"signature"})

    def canonical_unsigned_bytes(self) -> bytes:
        return _canonical_json(self.unsigned_payload())

    @property
    def digest(self) -> str:
        return _digest(self.canonical_unsigned_bytes())

    def verify_hmac(self, key: bytes) -> bool:
        return _verify_hmac(
            key, self.unsigned_payload(), self.signature, _ANSWER_DOMAIN
        )


class BusinessDecisionAnswerReceiptState(str, Enum):
    """A runner result for one answer.  No member claims a verified effect."""

    ANSWER_RECORDED = "answer_recorded"
    REFUSED = "refused"
    EXPIRED = "expired"
    SUPERSEDED = "superseded"
    DELIVERY_UNCERTAIN = "delivery_uncertain"


class BusinessDecisionAnswerReceiptReason(str, Enum):
    RECORDED_PENDING_REVALIDATION = "recorded_pending_revalidation"
    AUTHORIZATION_REFUSED = "authorization_refused"
    OPTION_REFUSED = "option_refused"
    EVIDENCE_REFUSED = "evidence_refused"
    REVALIDATION_REFUSED = "revalidation_refused"
    EXPIRED = "expired"
    SUPERSEDED = "superseded"
    DELIVERY_UNCERTAIN = "delivery_uncertain"


BUSINESS_DECISION_ANSWER_RECEIPT_REASONS: Mapping[
    BusinessDecisionAnswerReceiptState, frozenset[BusinessDecisionAnswerReceiptReason]
] = {
    BusinessDecisionAnswerReceiptState.ANSWER_RECORDED: frozenset(
        {BusinessDecisionAnswerReceiptReason.RECORDED_PENDING_REVALIDATION}
    ),
    BusinessDecisionAnswerReceiptState.REFUSED: frozenset(
        {
            BusinessDecisionAnswerReceiptReason.AUTHORIZATION_REFUSED,
            BusinessDecisionAnswerReceiptReason.OPTION_REFUSED,
            BusinessDecisionAnswerReceiptReason.EVIDENCE_REFUSED,
            BusinessDecisionAnswerReceiptReason.REVALIDATION_REFUSED,
        }
    ),
    BusinessDecisionAnswerReceiptState.EXPIRED: frozenset(
        {BusinessDecisionAnswerReceiptReason.EXPIRED}
    ),
    BusinessDecisionAnswerReceiptState.SUPERSEDED: frozenset(
        {BusinessDecisionAnswerReceiptReason.SUPERSEDED}
    ),
    BusinessDecisionAnswerReceiptState.DELIVERY_UNCERTAIN: frozenset(
        {BusinessDecisionAnswerReceiptReason.DELIVERY_UNCERTAIN}
    ),
}


class BusinessDecisionAnswerReceiptV1(_StrictContract):
    """A signed runner result that reports answer handling, not business success."""

    schema_version: Literal["openadapt.business-decision-answer-receipt/v1"] = (
        BUSINESS_DECISION_ANSWER_RECEIPT_SCHEMA
    )
    task_id: StrictStr = Field(pattern=_OPAQUE_ID_PATTERN)
    task_revision: StrictInt = Field(ge=1, le=2_147_483_647)
    task_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    request_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    answer_digest: StrictStr = Field(pattern=_SHA256_PATTERN)
    option_id: StrictStr = Field(pattern=_OPTION_ID_PATTERN)
    state: BusinessDecisionAnswerReceiptState
    reason_code: BusinessDecisionAnswerReceiptReason
    runner_decision_receipt_digest: StrictStr | None = Field(
        default=None, pattern=_SHA256_PATTERN
    )
    decided_at: StrictStr = Field(
        min_length=20, max_length=40, pattern=_TIMESTAMP_PATTERN
    )
    issuer_key_id: StrictStr = Field(pattern=_OPAQUE_ID_PATTERN)
    signature_algorithm: Literal["hmac-sha256"] = "hmac-sha256"
    signature: StrictStr = Field(pattern=_SIGNATURE_PATTERN)

    @model_validator(mode="after")
    def _validate_receipt(self) -> BusinessDecisionAnswerReceiptV1:
        if self.reason_code not in BUSINESS_DECISION_ANSWER_RECEIPT_REASONS[self.state]:
            raise ValueError("business decision receipt state and reason disagree")
        has_local_receipt = (
            self.state is BusinessDecisionAnswerReceiptState.ANSWER_RECORDED
            or self.reason_code is BusinessDecisionAnswerReceiptReason.REVALIDATION_REFUSED
        )
        if has_local_receipt:
            if self.runner_decision_receipt_digest is None:
                raise ValueError(
                    "an answer-recorded receipt requires the runner receipt digest"
                )
        elif self.runner_decision_receipt_digest is not None:
            raise ValueError(
                "a non-recorded result cannot claim a runner decision receipt"
            )
        _parse_timestamp(self.decided_at, "decided_at")
        return self

    @property
    def succeeded(self) -> Literal[False]:
        """A business-answer receipt never proves the workflow's business effect."""

        return False

    def unsigned_payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude={"signature"})

    def canonical_unsigned_bytes(self) -> bytes:
        return _canonical_json(self.unsigned_payload())

    @property
    def digest(self) -> str:
        return _digest(self.canonical_unsigned_bytes())

    def verify_hmac(self, key: bytes) -> bool:
        return _verify_hmac(
            key, self.unsigned_payload(), self.signature, _ANSWER_RECEIPT_DOMAIN
        )


def validate_business_decision_answer(
    task: BusinessDecisionTaskV1,
    answer: BusinessDecisionAnswerV1,
    *,
    task_signing_key: bytes,
    answer_signing_key: bytes,
    at: str,
) -> None:
    """Fail unless an authenticated answer matches one active remote task.

    This check does not authorize execution.  It is the portable admission
    check before the customer runner calls Flow's authoritative decision API.
    """

    if not task.verify_hmac(task_signing_key):
        raise ValueError("the business decision task signature is invalid")
    if not answer.verify_hmac(answer_signing_key):
        raise ValueError("the business decision answer signature is invalid")
    at_time = _parse_timestamp(at, "at")
    if task.delivery_mode is not BusinessDecisionDeliveryMode.REMOTE_ANSWERABLE:
        raise ValueError("this business decision requires a local answer")
    created_at = _parse_timestamp(task.created_at, "created_at")
    expires_at = _parse_timestamp(task.expires_at, "expires_at")
    if at_time < created_at:
        raise ValueError("the business decision task is not active yet")
    if at_time >= expires_at:
        raise ValueError("the business decision task expired")
    expected = {
        "task_id": (answer.task_id, task.task_id),
        "task_revision": (answer.task_revision, task.task_revision),
        "task_digest": (answer.task_digest, task.digest),
        "request_digest": (answer.request_digest, task.request_digest),
        "role_mapping_digest": (
            answer.role_mapping_digest,
            task.role_mapping_digest,
        ),
        "authn_assurance": (answer.authn_assurance, task.required_authn),
    }
    for name, (actual, required) in expected.items():
        if actual != required:
            raise ValueError(f"business decision {name} does not match the task")
    if answer.authenticated_role_ref not in set(task.authorized_role_refs):
        raise ValueError("the authenticated role is not authorized for the decision")
    if answer.authenticated_route_ref not in set(task.authorized_route_refs):
        raise ValueError("the authenticated route is not authorized for the decision")
    if answer.issuer_key_id not in set(task.authorized_answer_issuer_key_ids):
        raise ValueError("the answer signing key is not authorized for the decision")
    if answer.option_id not in {option.option_id for option in task.options}:
        raise ValueError("the business decision option is not permitted")
    answered_at = _parse_timestamp(answer.answered_at, "answered_at")
    if answered_at < created_at:
        raise ValueError("the business decision answer predates the task")
    if answered_at >= expires_at:
        raise ValueError("the business decision answer was created after expiry")
    if at_time < answered_at:
        raise ValueError("the business decision answer is from the future")


def sign_business_decision_task_hmac(
    *, key: bytes, fields: Mapping[str, Any]
) -> BusinessDecisionTaskV1:
    return _sign(BusinessDecisionTaskV1, key, fields, _TASK_DOMAIN)


def sign_business_decision_answer_hmac(
    *, key: bytes, fields: Mapping[str, Any]
) -> BusinessDecisionAnswerV1:
    return _sign(BusinessDecisionAnswerV1, key, fields, _ANSWER_DOMAIN)


def sign_business_decision_delivery_policy_hmac(
    *, key: bytes, fields: Mapping[str, Any]
) -> BusinessDecisionDeliveryPolicyV1:
    return _sign(
        BusinessDecisionDeliveryPolicyV1,
        key,
        fields,
        _DELIVERY_POLICY_DOMAIN,
    )


def sign_business_decision_answer_receipt_hmac(
    *, key: bytes, fields: Mapping[str, Any]
) -> BusinessDecisionAnswerReceiptV1:
    return _sign(BusinessDecisionAnswerReceiptV1, key, fields, _ANSWER_RECEIPT_DOMAIN)


def _sign(
    model: type[
        BusinessDecisionTaskV1
        | BusinessDecisionAnswerV1
        | BusinessDecisionDeliveryPolicyV1
        | BusinessDecisionAnswerReceiptV1
    ],
    key: bytes,
    fields: Mapping[str, Any],
    domain: bytes,
) -> (
    BusinessDecisionTaskV1
    | BusinessDecisionAnswerV1
    | BusinessDecisionDeliveryPolicyV1
    | BusinessDecisionAnswerReceiptV1
):
    _validate_hmac_key(key)
    if "signature" in fields:
        raise ValueError("fields must not contain a signature")
    validated = model.model_validate(
        {
            **dict(fields),
            "signature_algorithm": "hmac-sha256",
            "signature": "hmac-sha256:" + "0" * 64,
        }
    )
    signature = _hmac_signature(key, validated.unsigned_payload(), domain)
    return validated.model_copy(update={"signature": signature})


def _validate_hmac_key(key: bytes) -> None:
    if not isinstance(key, bytes) or len(key) < 32:
        raise ValueError("business decision HMAC key must contain at least 32 bytes")


def _parse_timestamp(value: str, field_name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an RFC 3339 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field_name} must include a timezone")
    return parsed


def _canonical_json(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _hmac_signature(key: bytes, payload: Mapping[str, Any], domain: bytes) -> str:
    return (
        "hmac-sha256:"
        + hmac.new(key, domain + _canonical_json(payload), hashlib.sha256).hexdigest()
    )


def _verify_hmac(
    key: bytes,
    payload: Mapping[str, Any],
    signature: str,
    domain: bytes,
) -> bool:
    _validate_hmac_key(key)
    return hmac.compare_digest(signature, _hmac_signature(key, payload, domain))
