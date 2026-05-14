import uuid

from fastapi import APIRouter
from fastapi import Depends
from sqlalchemy.orm import Session

from onyx.auth.permissions import require_permission
from onyx.db.engine.sql_engine import get_session
from onyx.db.enums import Permission
from onyx.db.external_app import create_external_app__no_commit
from onyx.db.external_app import delete_external_app__no_commit
from onyx.db.external_app import get_external_apps
from onyx.db.external_app import get_user_credentials_by_app_id
from onyx.db.external_app import required_user_credential_keys
from onyx.db.external_app import update_external_app__no_commit
from onyx.db.external_app import upsert_external_app_user_credential__no_commit
from onyx.db.models import ExternalApp
from onyx.db.models import ExternalAppUserCredential
from onyx.db.models import User
from onyx.server.features.build.api.models import ExternalAppAdminResponse
from onyx.server.features.build.api.models import ExternalAppUserResponse
from onyx.server.features.build.api.models import UpsertExternalAppRequest
from onyx.server.features.build.api.models import UpsertUserCredentialsRequest

router = APIRouter()


def _to_admin_response(app: ExternalApp) -> ExternalAppAdminResponse:
    # Display + lifecycle fields live on the linked Skill row.
    return ExternalAppAdminResponse(
        id=app.id,
        name=app.skill.name,
        description=app.skill.description,
        app_type=app.app_type,
        upstream_url_patterns=list(app.upstream_url_patterns),
        auth_template=app.auth_template,
        organization_credentials=app.organization_credentials,
        enabled=app.skill.enabled,
    )


def _to_user_response(
    app: ExternalApp, user_cred: ExternalAppUserCredential | None
) -> ExternalAppUserResponse:
    """Strip admin-only fields (auth_template, org_credentials) from
    the row and filter stored creds to keys the current template
    still requires, so stale entries from prior templates don't show."""
    required_keys = required_user_credential_keys(
        app.auth_template, app.organization_credentials
    )
    stored = user_cred.user_credentials if user_cred is not None else {}
    credential_values = {key: stored[key] for key in required_keys if key in stored}
    authenticated = all(key in credential_values for key in required_keys)

    return ExternalAppUserResponse(
        id=app.id,
        name=app.skill.name,
        description=app.skill.description,
        credential_keys=required_keys,
        credential_values=credential_values,
        authenticated=authenticated,
    )


# ── Admin endpoints ────────────────────────────────────────────────


@router.post("/admin/apps")
def upsert_external_app(
    request: UpsertExternalAppRequest,
    _: User = Depends(require_permission(Permission.FULL_ADMIN_PANEL_ACCESS)),
    db_session: Session = Depends(get_session),
) -> ExternalAppAdminResponse:
    """Create or update if `request.id` is set. 404 if id doesn't exist."""
    if request.id is not None:
        app = update_external_app__no_commit(
            db_session=db_session,
            external_app_id=request.id,
            name=request.name,
            description=request.description,
            enabled=request.enabled,
            app_type=request.app_type,
            upstream_url_patterns=request.upstream_url_patterns,
            auth_template=request.auth_template,
            organization_credentials=request.organization_credentials,
        )
    else:
        # Skill identity is server-derived: a fresh slug per instance
        # so multiple connections of the same provider don't collide;
        # default-public so every org user sees it once it's connected.
        # The bundle is intentionally empty for now — we'll attach the
        # provider's skill_bundles/<provider>/ blob when the rendering
        # path lands.
        slug = f"{request.app_type.value.lower()}-{uuid.uuid4().hex[:8]}"
        app = create_external_app__no_commit(
            db_session=db_session,
            slug=slug,
            name=request.name,
            description=request.description,
            bundle_file_id="",
            bundle_sha256="",
            enabled=request.enabled,
            is_public=True,
            app_type=request.app_type,
            upstream_url_patterns=request.upstream_url_patterns,
            auth_template=request.auth_template,
            organization_credentials=request.organization_credentials,
        )

    db_session.commit()
    return _to_admin_response(app)


@router.get("/admin/apps")
def list_external_apps_admin(
    _: User = Depends(require_permission(Permission.FULL_ADMIN_PANEL_ACCESS)),
    db_session: Session = Depends(get_session),
) -> list[ExternalAppAdminResponse]:
    apps = get_external_apps(db_session=db_session)
    return [_to_admin_response(app) for app in apps]


@router.delete("/admin/apps/{external_app_id}")
def delete_external_app(
    external_app_id: int,
    _: User = Depends(require_permission(Permission.FULL_ADMIN_PANEL_ACCESS)),
    db_session: Session = Depends(get_session),
) -> None:
    """Cascades to user-credential rows via FK ON DELETE CASCADE."""
    delete_external_app__no_commit(
        db_session=db_session, external_app_id=external_app_id
    )
    db_session.commit()


# ── User endpoints ─────────────────────────────────────────────────


@router.post("/apps/{external_app_id}/credentials")
def upsert_user_credentials(
    external_app_id: int,
    request: UpsertUserCredentialsRequest,
    user: User = Depends(require_permission(Permission.BASIC_ACCESS)),
    db_session: Session = Depends(get_session),
) -> None:
    upsert_external_app_user_credential__no_commit(
        db_session=db_session,
        external_app_id=external_app_id,
        user_id=user.id,
        user_credentials=request.user_credentials,
    )
    db_session.commit()


@router.get("/apps")
def list_external_apps(
    user: User = Depends(require_permission(Permission.BASIC_ACCESS)),
    db_session: Session = Depends(get_session),
) -> list[ExternalAppUserResponse]:
    apps = get_external_apps(db_session=db_session)
    user_creds_by_app = get_user_credentials_by_app_id(
        db_session=db_session, user_id=user.id
    )
    return [
        _to_user_response(app, user_creds_by_app.get(app.id))
        for app in apps
        if app.skill.enabled
    ]
