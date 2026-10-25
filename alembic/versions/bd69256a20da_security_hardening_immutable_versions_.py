"""security_hardening_immutable_versions_bound_invoice

Revision ID: bd69256a20da
Revises: 0ac36adacfdc
Create Date: 2026-10-25 08:04:20.921834

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'bd69256a20da'
down_revision: Union[str, Sequence[str], None] = '0ac36adacfdc'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('approvals', schema=None) as batch_op:
        batch_op.add_column(sa.Column('bound_invoice_reference', sa.String(length=100), nullable=True))
        batch_op.create_unique_constraint('uq_approval_payment_intent', ['payment_intent_id'])

    with op.batch_alter_table('vendor_versions', schema=None) as batch_op:
        batch_op.drop_column('superseded_at')


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('vendor_versions', schema=None) as batch_op:
        batch_op.add_column(sa.Column('superseded_at', sa.DATETIME(), nullable=True))

    with op.batch_alter_table('approvals', schema=None) as batch_op:
        batch_op.drop_constraint('uq_approval_payment_intent', type_='unique')
        batch_op.drop_column('bound_invoice_reference')
