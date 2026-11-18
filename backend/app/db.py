from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

from .config import settings


def now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Program(Base):
    __tablename__ = 'programs'
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(200))
    policy: Mapped[dict] = mapped_column(JSON)
    secrets: Mapped[str] = mapped_column(Text, default='')
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Scan(Base):
    __tablename__ = 'scans'
    id: Mapped[int] = mapped_column(primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey('programs.id'))
    target: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default='queued')
    options: Mapped[dict] = mapped_column(JSON)
    request_count: Mapped[int] = mapped_column(Integer, default=0)
    inventory: Mapped[dict] = mapped_column(JSON, default=dict)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Finding(Base):
    __tablename__ = 'findings'
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey('scans.id'))
    category: Mapped[str] = mapped_column(String(80))
    title: Mapped[str] = mapped_column(String(240))
    endpoint: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(30), default='potential')
    evidence: Mapped[dict] = mapped_column(JSON)
    description: Mapped[str] = mapped_column(Text)
    impact: Mapped[str] = mapped_column(Text)
    remediation: Mapped[str] = mapped_column(Text)
    steps: Mapped[list] = mapped_column(JSON)
    cvss: Mapped[str | None] = mapped_column(String(100))
    review_note: Mapped[str] = mapped_column(Text, default='')
    ai_analysis: Mapped[dict | None] = mapped_column(JSON)
    eligibility: Mapped[str] = mapped_column(String(100), default='Human policy review required')
    submission: Mapped[str] = mapped_column(String(30), default='draft')
    submission_url: Mapped[str] = mapped_column(Text, default='')
    reward_currency: Mapped[str] = mapped_column(String(3), default='USD')
    earned_cents: Mapped[int] = mapped_column(Integer, default=0)
    pending_cents: Mapped[int] = mapped_column(Integer, default=0)


class Audit(Base):
    __tablename__ = 'audit'
    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int | None] = mapped_column(ForeignKey('scans.id'))
    event: Mapped[str] = mapped_column(String(80))
    details: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)


class Callback(Base):
    __tablename__ = 'callbacks'
    token: Mapped[str] = mapped_column(String(100), primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey('scans.id'))
    endpoint: Mapped[str] = mapped_column(Text)
    parameter: Mapped[str] = mapped_column(String(200))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    received_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


settings.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
engine = create_engine(settings.database_url,
                       connect_args={'check_same_thread': False} if settings.database_url.startswith('sqlite') else {})
Session = sessionmaker(engine, expire_on_commit=False)


def audit(event: str, details: dict, scan_id: int | None = None) -> None:
    with Session.begin() as db:
        db.add(Audit(event=event, details=details, scan_id=scan_id))
