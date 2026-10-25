"""add_case_type_and_nullable_proposed_recipient

Revision ID: 13034b7cc906
Revises: bd69256a20da
Create Date: 2026-10-25 19:02:22.312298

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '13034b7cc906'
down_revision: Union[str, Sequence[str], None] = 'bd69256a20da'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
    Upgrade schema:
    1. Add case_type column with default 'RECIPIENT_CHANGE_PROPOSAL' to payee_change_cases.
    2. Change proposed_recipient column to nullable=True (to allow NULL for MANUAL_EXTRACTION_REVIEW cases).
    3. Use batch_alter_table for full SQLite compatibility.
    4. Re-ensure immutable vendor_versions triggers are intact.
    """
    with op.batch_alter_table('payee_change_cases', schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                'case_type',
                sa.String(length=50),
                nullable=False,
                server_default='RECIPIENT_CHANGE_PROPOSAL',
            )
        )
        batch_op.alter_column(
            'proposed_recipient',
            existing_type=sa.String(length=255),
            nullable=True,
        )

    # Re-verify/re-create SQLite immutability triggers on vendor_versions
    op.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_prevent_vendor_version_update
        BEFORE UPDATE ON vendor_versions
        BEGIN
            SELECT RAISE(ABORT, 'VendorVersion rows are strictly immutable and cannot be updated.');
        END;
    """)
    op.execute("""
        CREATE TRIGGER IF NOT EXISTS trg_prevent_vendor_version_delete
        BEFORE DELETE ON vendor_versions
        BEGIN
            SELECT RAISE(ABORT, 'VendorVersion rows are strictly immutable and cannot be deleted.');
        END;
    """)


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('payee_change_cases', schema=None) as batch_op:
        batch_op.alter_column(
            'proposed_recipient',
            existing_type=sa.String(length=255),
            nullable=False,
        )
        batch_op.drop_column('case_type')
