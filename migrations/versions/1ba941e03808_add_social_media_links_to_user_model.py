"""Add social media links to User model

Revision ID: 1ba941e03808
Revises: 0041ca8380e5
Create Date: 2025-06-12 16:28:44.190587

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1ba941e03808'
down_revision = '0041ca8380e5'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('twitter_url', sa.String(length=200), nullable=True))
        batch_op.add_column(sa.Column('facebook_url', sa.String(length=200), nullable=True))
        batch_op.add_column(sa.Column('linkedin_url', sa.String(length=200), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('linkedin_url')
        batch_op.drop_column('facebook_url')
        batch_op.drop_column('twitter_url')

    # ### end Alembic commands ###
