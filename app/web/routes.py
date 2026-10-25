"""
app/web/routes.py — VendorTrust FastAPI route handlers.

Security Invariants enforced in every handler:
1. PUBLIC_DEMO sessions use isolated per-session in-memory SQLite + MockPayoutProvider ONLY.
2. PRIVATE_SANDBOX requires server-verified operator token; never exposed to public users.
3. Every payout resolves recipient exclusively from immutable, approved VendorVersion.
4. AI output is advisory; never overrides deterministic hold decisions.
5. Simulated and AI outputs are labeled explicitly with actual provider (GEMINI / HEURISTIC).
6. CSRF validation enforced on state-changing POST requests.
7. Out-of-band verification is cleanly separated into a dedicated Simulated Vendor Mailbox.
"""
import datetime
import json
from typing import Optional

from fastapi import APIRouter, Cookie, Depends, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.config import APP_ENV, OPERATOR_API_KEY
from app.models import (
    AuditEvent,
    Approval,
    PayeeChangeCase,
    PaymentIntent,
    PayoutAttempt,
    VendorVersion,
    Vendor,
    VerificationChallenge,
    utcnow,
)
from app.services.ai_extract import extract_candidate_payee_change
from app.services.approvals import (
    approve_payment_intent,
    approve_payee_change_case,
    create_payment_intent,
)
from app.services.challenges import (
    create_payee_change_case,
    issue_verification_challenge,
    record_vendor_rejection_compromise,
    verify_vendor_confirmation,
)
from app.services.exceptions import (
    DuplicatePayoutError,
    ExpiredChallengeError,
    InvalidChallengeError,
    InvalidStateTransitionError,
    MaxAttemptsExceededError,
    SecurityViolationError,
    VendorFrozenError,
)
from app.services.intake import process_incoming_document
from app.services.payouts import MockPayoutProvider, submit_approved_payout
from app.services.policy import PolicyDecision
from app.services.vendor_registry import get_vendor
from app.web.deps import DemoContext, assert_csrf, require_demo_context
from app.web.session import (
    new_demo_session,
    destroy_demo_session,
    store_simulated_challenge_otp,
    get_simulated_challenge_otp,
    consume_simulated_challenge_otp,
)

router = APIRouter()
templates = Jinja2Templates(directory="app/templates")

SECURE_COOKIES = (APP_ENV in ("production", "prod"))

# ──────────────────────────────────────────────────────────────────────────────
# Jinja2 globals
# ──────────────────────────────────────────────────────────────────────────────

def _badge_state(state: str) -> str:
    mapping = {
        "HELD": "badge-held",
        "CHALLENGE_ISSUED": "badge-challenge",
        "VENDOR_CONFIRMED": "badge-confirmed",
        "VERSION_ACTIVATED": "badge-activated",
        "REJECTED_COMPROMISE_SUSPECTED": "badge-rejected",
        "EXPIRED": "badge-invalidated",
        "APPROVED": "badge-approved",
        "AWAITING_APPROVAL": "badge-awaiting",
        "INVALIDATED": "badge-invalidated",
        "SUCCESS": "badge-success",
        "SETTLED": "badge-settled",
        "FAILED": "badge-failed",
        "RESERVED": "badge-pending",
        "PENDING": "badge-pending",
        "RECONCILE_REQUIRED": "badge-warning",
    }
    return mapping.get(state, "badge-held")

templates.env.globals["badge_cls"] = _badge_state

def _short_id(s: str) -> str:
    return s[:8] + "…" if s and len(s) > 8 else s

templates.env.globals["short_id"] = _short_id

def _fmt_dt(dt) -> str:
    if not dt:
        return "—"
    if hasattr(dt, "strftime"):
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    return str(dt)[:16]

templates.env.globals["fmt_dt"] = _fmt_dt


# ──────────────────────────────────────────────────────────────────────────────
# Landing / session init
# ──────────────────────────────────────────────────────────────────────────────

@router.get("/", response_class=HTMLResponse)
async def landing(request: Request, demo_session: Optional[str] = Cookie(None)):
    """Landing page. Starts or validates a PUBLIC_DEMO session."""
    valid = False
    if demo_session:
        from app.web.session import get_demo_session_db
        db, meta = get_demo_session_db(demo_session)
        if db is not None:
            valid = True
            db.close()
    return templates.TemplateResponse(request=request, name="landing.html", context={
        "has_session": valid,
    })


@router.post("/start-demo", response_class=HTMLResponse)
async def start_demo(request: Request):
    """Create a fresh isolated PUBLIC_DEMO session."""
    token = new_demo_session()
    resp = RedirectResponse(url="/inbox", status_code=303)
    resp.set_cookie(
        "demo_session",
        token,
        httponly=True,
        samesite="lax",
        secure=SECURE_COOKIES,
        max_age=7200,
    )
    return resp


@router.post("/reset-demo", response_class=HTMLResponse)
async def reset_demo(
    request: Request,
    demo_session: Optional[str] = Cookie(None),
    csrf_token: Optional[str] = Form(None),
):
    """Destroy current demo session and start fresh."""
    if demo_session:
        # Validate CSRF if session existed
        from app.web.session import validate_csrf_token, get_demo_session_db
        db, meta = get_demo_session_db(demo_session)
        if db is not None:
            db.close()
            if not csrf_token or not validate_csrf_token(demo_session, csrf_token):
                raise HTTPException(status_code=403, detail="Invalid or missing CSRF token for demo reset.")
        destroy_demo_session(demo_session)

    token = new_demo_session()
    resp = RedirectResponse(url="/inbox", status_code=303)
    resp.set_cookie(
        "demo_session",
        token,
        httponly=True,
        samesite="lax",
        secure=SECURE_COOKIES,
        max_age=7200,
    )
    return resp


# ──────────────────────────────────────────────────────────────────────────────
# Inbox — Document / Invoice Intake
# ──────────────────────────────────────────────────────────────────────────────

@router.get("/inbox", response_class=HTMLResponse)
async def inbox(request: Request, ctx: DemoContext = Depends(require_demo_context)):
    db = ctx.db
    vendor = db.query(Vendor).filter_by(id=ctx.vendor_id).first()
    cases = db.query(PayeeChangeCase).filter_by(vendor_id=ctx.vendor_id).order_by(
        PayeeChangeCase.created_at.desc()
    ).all()
    intents = db.query(PaymentIntent).filter_by(vendor_id=ctx.vendor_id).order_by(
        PaymentIntent.created_at.desc()
    ).limit(5).all()
    return templates.TemplateResponse(request=request, name="inbox.html", context={
        "vendor": vendor,
        "cases": cases,
        "intents": intents,
        "asha_id": ctx.asha_id,
        "ravi_id": ctx.ravi_id,
        "csrf_token": ctx.csrf_token,
    })


@router.post("/inbox/submit", response_class=HTMLResponse)
async def inbox_submit(
    request: Request,
    document_text: str = Form(...),
    source_type: str = Form("email_text"),
    use_ai: str = Form("0"),
    csrf_token: Optional[str] = Form(None),
    ctx: DemoContext = Depends(require_demo_context),
):
    """Process an incoming invoice or email through the deterministic intake pipeline."""
    assert_csrf(ctx, csrf_token)
    db = ctx.db
    force_heuristic = (use_ai != "1")

    try:
        result = process_incoming_document(
            session=db,
            vendor_id=ctx.vendor_id,
            untrusted_text=document_text,
            source_type=source_type,
            source_reference=f"WEB-{utcnow().strftime('%Y%m%d%H%M%S')}",
            requester_id=ctx.asha_id,
            force_heuristic=force_heuristic,
        )
    except Exception as e:
        return templates.TemplateResponse(request=request, name="inbox.html", context={
            "error": str(e),
            "vendor": db.query(Vendor).filter_by(id=ctx.vendor_id).first(),
            "cases": db.query(PayeeChangeCase).filter_by(vendor_id=ctx.vendor_id).order_by(
                PayeeChangeCase.created_at.desc()
            ).all(),
            "intents": [],
            "asha_id": ctx.asha_id,
            "ravi_id": ctx.ravi_id,
            "csrf_token": ctx.csrf_token,
        })

    return templates.TemplateResponse(request=request, name="intake_result.html", context={
        "result": result,
        "document_text": document_text[:500],
        "asha_id": ctx.asha_id,
        "ravi_id": ctx.ravi_id,
        "csrf_token": ctx.csrf_token,
    })


# ──────────────────────────────────────────────────────────────────────────────
# Payee Change Cases
# ──────────────────────────────────────────────────────────────────────────────

@router.get("/cases", response_class=HTMLResponse)
async def list_cases(request: Request, ctx: DemoContext = Depends(require_demo_context)):
    db = ctx.db
    cases = db.query(PayeeChangeCase).filter_by(vendor_id=ctx.vendor_id).order_by(
        PayeeChangeCase.created_at.desc()
    ).all()
    return templates.TemplateResponse(request=request, name="cases.html", context={
        "cases": cases,
        "asha_id": ctx.asha_id,
        "ravi_id": ctx.ravi_id,
        "csrf_token": ctx.csrf_token,
    })


@router.get("/cases/{case_id}", response_class=HTMLResponse)
async def case_detail(
    request: Request,
    case_id: str,
    ctx: DemoContext = Depends(require_demo_context),
):
    db = ctx.db
    case = db.query(PayeeChangeCase).filter_by(id=case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")

    vendor = db.query(Vendor).filter_by(id=case.vendor_id).first()
    base_version = db.query(VendorVersion).filter_by(id=case.base_version_id).first()

    challenge = (
        db.query(VerificationChallenge)
        .filter_by(case_id=case_id)
        .order_by(VerificationChallenge.created_at.desc())
        .first()
    )

    audit = db.query(AuditEvent).filter_by(entity_id=case_id).order_by(
        AuditEvent.created_at.asc()
    ).all()

    return templates.TemplateResponse(request=request, name="case_detail.html", context={
        "case": case,
        "vendor": vendor,
        "base_version": base_version,
        "challenge": challenge,
        "audit": audit,
        "asha_id": ctx.asha_id,
        "ravi_id": ctx.ravi_id,
        "csrf_token": ctx.csrf_token,
    })


@router.post("/cases/{case_id}/issue-challenge", response_class=HTMLResponse)
async def issue_challenge(
    request: Request,
    case_id: str,
    csrf_token: Optional[str] = Form(None),
    ctx: DemoContext = Depends(require_demo_context),
):
    """Issue out-of-band HMAC-keyed verification challenge to trusted vendor contact."""
    assert_csrf(ctx, csrf_token)
    db = ctx.db
    try:
        challenge, raw_token = issue_verification_challenge(
            session=db,
            case_id=case_id,
            actor_id=ctx.asha_id,
            expiry_seconds=900,
        )
        db.commit()
    except Exception as e:
        raise HTTPException(400, str(e))

    # Store plaintext OTP only in ephemeral session-scoped mailbox store.
    # The challenge DB table retains only the keyed HMAC.
    store_simulated_challenge_otp(
        session_token=ctx.session_token,
        case_id=case_id,
        raw_token=raw_token,
        expires_at=challenge.expires_at,
    )

    return templates.TemplateResponse(request=request, name="challenge_issued.html", context={
        "case_id": case_id,
        "challenge": challenge,
        # raw_token NOT passed here — requester sees only link to vendor mailbox
        "asha_id": ctx.asha_id,
        "ravi_id": ctx.ravi_id,
        "csrf_token": ctx.csrf_token,
    })


@router.get("/cases/{case_id}/vendor-mailbox", response_class=HTMLResponse)
async def vendor_simulated_mailbox(
    request: Request,
    case_id: str,
    ctx: DemoContext = Depends(require_demo_context),
):
    """
    Dedicated view for Simulated Vendor External Mailbox (Demo Persona: Vendor Contact).
    Explicitly separated from the requester view to demonstrate trust boundaries honestly.
    Retrieves plaintext OTP from ephemeral session-scoped mailbox store — never from DB.
    """
    db = ctx.db
    case = db.query(PayeeChangeCase).filter_by(id=case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")

    vendor = db.query(Vendor).filter_by(id=case.vendor_id).first()
    challenge = (
        db.query(VerificationChallenge)
        .filter_by(case_id=case_id)
        .order_by(VerificationChallenge.created_at.desc())
        .first()
    )

    # Retrieve ephemeral plaintext OTP from session mailbox (never from DB)
    otp_for_display = get_simulated_challenge_otp(ctx.session_token, case_id)

    return templates.TemplateResponse(request=request, name="vendor_mailbox.html", context={
        "case": case,
        "vendor": vendor,
        "challenge": challenge,
        "otp_for_display": otp_for_display,
        "asha_id": ctx.asha_id,
        "ravi_id": ctx.ravi_id,
        "csrf_token": ctx.csrf_token,
    })


@router.post("/cases/{case_id}/verify", response_class=HTMLResponse)
async def verify_challenge(
    request: Request,
    case_id: str,
    submitted_token: str = Form(...),
    csrf_token: Optional[str] = Form(None),
    ctx: DemoContext = Depends(require_demo_context),
):
    """Vendor confirms change by submitting received OTP token."""
    assert_csrf(ctx, csrf_token)
    db = ctx.db
    try:
        case = verify_vendor_confirmation(
            session=db,
            case_id=case_id,
            submitted_token=submitted_token,
        )
        db.commit()
    except (InvalidChallengeError, MaxAttemptsExceededError, ExpiredChallengeError) as e:
        raise HTTPException(400, str(e))

    # Consume and purge ephemeral plaintext OTP after successful verification
    consume_simulated_challenge_otp(ctx.session_token, case_id)
    return RedirectResponse(url=f"/cases/{case_id}", status_code=303)


@router.post("/cases/{case_id}/reject-compromise", response_class=HTMLResponse)
async def reject_compromise(
    request: Request,
    case_id: str,
    csrf_token: Optional[str] = Form(None),
    ctx: DemoContext = Depends(require_demo_context),
):
    """Vendor flags change as 'This wasn't me' — triggers REJECTED_COMPROMISE and freezes vendor."""
    assert_csrf(ctx, csrf_token)
    db = ctx.db
    try:
        record_vendor_rejection_compromise(
            session=db,
            case_id=case_id,
            actor_note="Vendor clicked 'This wasn't me' via simulated vendor mailbox",
        )
        db.commit()
    except Exception as e:
        raise HTTPException(400, str(e))

    # Consume and purge ephemeral plaintext OTP on compromise report
    consume_simulated_challenge_otp(ctx.session_token, case_id)
    return RedirectResponse(url=f"/cases/{case_id}", status_code=303)


@router.post("/cases/{case_id}/approve", response_class=HTMLResponse)
async def approver_approve_case(
    request: Request,
    case_id: str,
    csrf_token: Optional[str] = Form(None),
    ctx: DemoContext = Depends(require_demo_context),
):
    """Approver (Ravi) independently activates the vendor-confirmed change, creating v(n+1)."""
    assert_csrf(ctx, csrf_token)
    db = ctx.db
    try:
        activated_case, new_version = approve_payee_change_case(
            session=db,
            case_id=case_id,
            approver_id=ctx.ravi_id,
        )
        db.commit()
    except (SecurityViolationError, InvalidStateTransitionError) as e:
        raise HTTPException(400, str(e))

    return RedirectResponse(url=f"/cases/{case_id}?approved=1", status_code=303)


# ──────────────────────────────────────────────────────────────────────────────
# Payment Intents
# ──────────────────────────────────────────────────────────────────────────────

@router.get("/payments", response_class=HTMLResponse)
async def list_payments(request: Request, ctx: DemoContext = Depends(require_demo_context)):
    db = ctx.db
    vendor = db.query(Vendor).filter_by(id=ctx.vendor_id).first()
    active_version = db.query(VendorVersion).filter_by(id=vendor.active_version_id).first()
    intents = db.query(PaymentIntent).filter_by(vendor_id=ctx.vendor_id).order_by(
        PaymentIntent.created_at.desc()
    ).all()
    return templates.TemplateResponse(request=request, name="payments.html", context={
        "vendor": vendor,
        "active_version": active_version,
        "intents": intents,
        "asha_id": ctx.asha_id,
        "ravi_id": ctx.ravi_id,
        "csrf_token": ctx.csrf_token,
    })


@router.post("/payments/create", response_class=HTMLResponse)
async def create_intent(
    request: Request,
    invoice_reference: str = Form(...),
    amount_minor: int = Form(...),
    currency: str = Form("USD"),
    csrf_token: Optional[str] = Form(None),
    ctx: DemoContext = Depends(require_demo_context),
):
    """Requester (Asha) creates a payment intent bound to active vendor version."""
    assert_csrf(ctx, csrf_token)
    db = ctx.db
    try:
        intent = create_payment_intent(
            session=db,
            vendor_id=ctx.vendor_id,
            invoice_reference=invoice_reference,
            amount_minor=amount_minor,
            currency=currency,
            requester_id=ctx.asha_id,
        )
        db.commit()
    except (SecurityViolationError, VendorFrozenError, ValueError) as e:
        raise HTTPException(400, str(e))

    return RedirectResponse(url=f"/payments/{intent.id}", status_code=303)


@router.get("/payments/{intent_id}", response_class=HTMLResponse)
async def payment_detail(
    request: Request,
    intent_id: str,
    ctx: DemoContext = Depends(require_demo_context),
):
    db = ctx.db
    intent = db.query(PaymentIntent).filter_by(id=intent_id).first()
    if not intent:
        raise HTTPException(404, "Payment intent not found")

    vendor = db.query(Vendor).filter_by(id=intent.vendor_id).first()
    version = db.query(VendorVersion).filter_by(id=intent.vendor_version_id).first()
    approval = db.query(Approval).filter_by(payment_intent_id=intent_id).first() if intent.approval_id else None
    attempts = db.query(PayoutAttempt).filter_by(payment_intent_id=intent_id).all()
    audit = db.query(AuditEvent).filter_by(entity_id=intent_id).order_by(
        AuditEvent.created_at.asc()
    ).all()

    return templates.TemplateResponse(request=request, name="payment_detail.html", context={
        "intent": intent,
        "vendor": vendor,
        "version": version,
        "approval": approval,
        "attempts": attempts,
        "audit": audit,
        "asha_id": ctx.asha_id,
        "ravi_id": ctx.ravi_id,
        "csrf_token": ctx.csrf_token,
    })


@router.post("/payments/{intent_id}/approve", response_class=HTMLResponse)
async def approver_approve_intent(
    request: Request,
    intent_id: str,
    csrf_token: Optional[str] = Form(None),
    ctx: DemoContext = Depends(require_demo_context),
):
    """Approver (Ravi) authorizes the payment intent. Requester cannot approve own intent."""
    assert_csrf(ctx, csrf_token)
    db = ctx.db
    try:
        approve_payment_intent(
            session=db,
            payment_intent_id=intent_id,
            approver_id=ctx.ravi_id,
        )
        db.commit()
    except (SecurityViolationError, InvalidStateTransitionError, VendorFrozenError) as e:
        raise HTTPException(400, str(e))

    return RedirectResponse(url=f"/payments/{intent_id}", status_code=303)


@router.post("/payments/{intent_id}/execute", response_class=HTMLResponse)
async def execute_payment(
    request: Request,
    intent_id: str,
    csrf_token: Optional[str] = Form(None),
    ctx: DemoContext = Depends(require_demo_context),
):
    """
    Execute payout. PUBLIC_DEMO: strictly uses MockPayoutProvider.
    Recipient resolved exclusively from immutable approved VendorVersion.
    Simulated payout is labeled clearly in the response.
    """
    assert_csrf(ctx, csrf_token)
    db = ctx.db
    # INVARIANT: In PUBLIC_DEMO, ALWAYS use MockPayoutProvider. Never real PayPal.
    mock_provider = MockPayoutProvider(desired_item_status="SUCCESS")
    try:
        attempt = submit_approved_payout(
            session=db,
            payment_intent_id=intent_id,
            operator_actor_id=ctx.ravi_id,
            provider=mock_provider,
        )
        db.commit()
    except (SecurityViolationError, InvalidStateTransitionError, DuplicatePayoutError, VendorFrozenError) as e:
        raise HTTPException(400, str(e))

    return RedirectResponse(url=f"/payments/{intent_id}?executed=1", status_code=303)


# ──────────────────────────────────────────────────────────────────────────────
# Audit Timeline
# ──────────────────────────────────────────────────────────────────────────────

@router.get("/audit", response_class=HTMLResponse)
async def audit_timeline(request: Request, ctx: DemoContext = Depends(require_demo_context)):
    db = ctx.db
    events = db.query(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(50).all()
    return templates.TemplateResponse(request=request, name="audit.html", context={
        "events": events,
        "asha_id": ctx.asha_id,
        "ravi_id": ctx.ravi_id,
        "csrf_token": ctx.csrf_token,
    })


# ──────────────────────────────────────────────────────────────────────────────
# Vendor versions overview
# ──────────────────────────────────────────────────────────────────────────────

@router.get("/vendor", response_class=HTMLResponse)
async def vendor_detail(request: Request, ctx: DemoContext = Depends(require_demo_context)):
    db = ctx.db
    vendor = db.query(Vendor).filter_by(id=ctx.vendor_id).first()
    versions = db.query(VendorVersion).filter_by(vendor_id=ctx.vendor_id).order_by(
        VendorVersion.version_number.asc()
    ).all()
    active_version = db.query(VendorVersion).filter_by(id=vendor.active_version_id).first()
    return templates.TemplateResponse(request=request, name="vendor.html", context={
        "vendor": vendor,
        "versions": versions,
        "active_version": active_version,
        "asha_id": ctx.asha_id,
        "ravi_id": ctx.ravi_id,
        "csrf_token": ctx.csrf_token,
    })
