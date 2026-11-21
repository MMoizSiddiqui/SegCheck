"""Controlled policy lifecycle transitions with persistent audit events."""

from sqlalchemy.exc import IntegrityError

from segcheck_web.extensions import db
from segcheck_web.models import Policy, PolicyLifecycleEvent


VALID_STATUSES = frozenset({"draft", "active", "archived"})

ALLOWED_TRANSITIONS = {
    "draft": frozenset({"active", "archived"}),
    "active": frozenset({"draft", "archived"}),
    "archived": frozenset(),
}


class PolicyLifecycleError(ValueError):
    """Raised when a policy lifecycle transition cannot be completed."""


class PolicyLifecycleNotFoundError(PolicyLifecycleError):
    """Raised when the requested policy does not exist."""


class PolicyLifecycleArchivedError(PolicyLifecycleError):
    """Raised when an archived policy is asked to transition again."""


class PolicyLifecycleTransitionError(PolicyLifecycleError):
    """Raised when a requested lifecycle transition is not permitted."""


def transition_policy_status(
    policy_id,
    to_status,
    reason,
    actor_identifier=None,
):
    """Transition a policy and append its audit event atomically.

    Archived policies are terminal. A transition requires a meaningful
    reason. Actor identity remains optional until authentication exists.
    """
    if (
        isinstance(policy_id, bool)
        or not isinstance(policy_id, int)
        or policy_id < 1
    ):
        raise PolicyLifecycleError("Policy ID must be a positive integer")

    if not isinstance(to_status, str) or to_status not in VALID_STATUSES:
        raise PolicyLifecycleTransitionError("Requested policy status is invalid")

    if not isinstance(reason, str):
        raise PolicyLifecycleError("A transition reason must be provided")

    reason = reason.strip()
    if not reason:
        raise PolicyLifecycleError("A transition reason must not be blank")

    if len(reason) > 500:
        raise PolicyLifecycleError(
            "Transition reason must not exceed 500 characters"
        )

    if actor_identifier is not None:
        if not isinstance(actor_identifier, str):
            raise PolicyLifecycleError("Actor identifier must be text")

        actor_identifier = actor_identifier.strip()

        if not actor_identifier:
            raise PolicyLifecycleError(
                "Actor identifier must not be blank when supplied"
            )

        if len(actor_identifier) > 128:
            raise PolicyLifecycleError(
                "Actor identifier must not exceed 128 characters"
            )

    try:
        policy = (
            db.session.query(Policy)
            .filter_by(id=policy_id)
            .with_for_update()
            .one_or_none()
        )

        if policy is None:
            raise PolicyLifecycleNotFoundError("Policy does not exist")

        from_status = policy.status

        if from_status == "archived":
            raise PolicyLifecycleArchivedError(
                "Archived policies cannot transition to another status"
            )

        if to_status == from_status:
            raise PolicyLifecycleTransitionError(
                "Policy is already in the requested status"
            )

        if to_status not in ALLOWED_TRANSITIONS.get(from_status, frozenset()):
            raise PolicyLifecycleTransitionError(
                f"Transition from {from_status!r} to {to_status!r} "
                "is not permitted"
            )

        event = PolicyLifecycleEvent(
            policy_id=policy.id,
            from_status=from_status,
            to_status=to_status,
            reason=reason,
            actor_identifier=actor_identifier,
        )

        policy.status = to_status
        db.session.add(event)
        db.session.commit()

        return event

    except IntegrityError as exc:
        db.session.rollback()
        raise PolicyLifecycleError(
            "The lifecycle transition could not be saved because a "
            "database integrity constraint was violated"
        ) from exc

    except Exception:
        db.session.rollback()
        raise
