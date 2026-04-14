"""
Email Alerter - Sends alerts via SMTP or SendGrid.
"""

import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import List, Optional

import structlog

from ..models.incidents import Incident
from ..explainability.explanation import Explanation

logger = structlog.get_logger()


class EmailAlerter:
    """
    Sends formatted alerts via email.

    Supports two providers:
    - SMTP (default) — via aiosmtplib
    - SendGrid — via HTTP API
    """

    def __init__(
        self,
        provider: str = "smtp",
        # SMTP
        smtp_host: Optional[str] = None,
        smtp_port: int = 587,
        smtp_user: Optional[str] = None,
        smtp_password: Optional[str] = None,
        smtp_use_tls: bool = True,
        # SendGrid
        sendgrid_api_key: Optional[str] = None,
        # Common
        from_email: Optional[str] = None,
        to_emails: Optional[List[str]] = None,
        dashboard_url: str = "https://xdr.example.com",
    ):
        self.provider = provider

        # SMTP config
        self.smtp_host = smtp_host or os.getenv("SMTP_HOST", "")
        self.smtp_port = int(smtp_port or os.getenv("SMTP_PORT", "587"))
        self.smtp_user = smtp_user or os.getenv("SMTP_USER", "")
        self.smtp_password = smtp_password or os.getenv("SMTP_PASSWORD", "")
        self.smtp_use_tls = smtp_use_tls

        # SendGrid config
        self.sendgrid_api_key = sendgrid_api_key or os.getenv("SENDGRID_API_KEY", "")

        # Common
        self.from_email = from_email or os.getenv("ALERT_FROM_EMAIL", "sentinel3@alerts.local")
        raw_to = to_emails or os.getenv("ALERT_TO_EMAILS", "").split(",")
        self.to_emails: List[str] = [e.strip() for e in raw_to if e.strip()]

        self.dashboard_url = dashboard_url

    # ── Public interface (matches Slack/Telegram pattern) ──────────

    async def send_critical(self, incident: Incident, explanation: Explanation):
        """Send critical alert email."""
        subject = f"[Sentinel3 CRITICAL] {explanation.title}"
        html = self._build_html(incident, explanation, "CRITICAL")
        await self._send(subject, html)
        logger.info("email_critical_sent", incident_id=incident.id)

    async def send_high(self, incident: Incident, explanation: Explanation):
        """Send high-severity alert email."""
        subject = f"[Sentinel3 HIGH] {explanation.title}"
        html = self._build_html(incident, explanation, "HIGH")
        await self._send(subject, html)
        logger.info("email_high_sent", incident_id=incident.id)

    async def send_info(self, incident: Incident, explanation: Explanation):
        """Send informational alert email."""
        subject = f"[Sentinel3 {incident.severity.name}] {explanation.title}"
        html = self._build_html(incident, explanation, incident.severity.name)
        await self._send(subject, html)
        logger.info("email_info_sent", incident_id=incident.id)

    # ── HTML builder ───────────────────────────────────────────────

    def _build_html(
        self,
        incident: Incident,
        explanation: Explanation,
        severity_label: str,
    ) -> str:
        severity_colors = {
            "CRITICAL": "#EF4444",
            "HIGH": "#F97316",
            "MEDIUM": "#EAB308",
            "LOW": "#3B82F6",
            "INFO": "#6B7280",
        }
        color = severity_colors.get(severity_label.upper(), "#6B7280")

        chains = ", ".join(incident.affected_chains) if incident.affected_chains else "N/A"

        actions_html = ""
        urgent = [a for a in explanation.recommended_actions if a.is_urgent][:5]
        if urgent:
            items = "".join(f"<li>{a.action}</li>" for a in urgent)
            actions_html = f"<h3 style='color:#e5e7eb;'>Recommended Actions</h3><ul>{items}</ul>"

        return f"""
        <html><body style="font-family: Arial, sans-serif; background: #0a0a0f; color: #e5e7eb; padding: 20px;">
        <div style="max-width: 600px; margin: 0 auto; background: #1a1a2e; border-radius: 12px; padding: 24px; border: 1px solid #2a2a4a;">
            <h1 style="color: {color}; margin-top: 0;">Sentinel3 Alert</h1>
            <div style="background: {color}20; border-left: 4px solid {color}; padding: 12px; border-radius: 4px; margin-bottom: 16px;">
                <strong style="color: {color};">{severity_label}</strong> &mdash; {explanation.title}
            </div>
            <table style="width: 100%; border-collapse: collapse;">
                <tr><td style="padding: 8px; color: #9ca3af;">Incident ID</td><td style="padding: 8px;">{incident.id}</td></tr>
                <tr><td style="padding: 8px; color: #9ca3af;">Attack Type</td><td style="padding: 8px;">{incident.attack_type.value}</td></tr>
                <tr><td style="padding: 8px; color: #9ca3af;">Confidence</td><td style="padding: 8px;">{explanation.confidence:.0%}</td></tr>
                <tr><td style="padding: 8px; color: #9ca3af;">Estimated Loss</td><td style="padding: 8px;">${incident.total_loss_usd:,.2f}</td></tr>
                <tr><td style="padding: 8px; color: #9ca3af;">TVL at Risk</td><td style="padding: 8px;">${incident.tvl_at_risk_usd:,.2f}</td></tr>
                <tr><td style="padding: 8px; color: #9ca3af;">Chains</td><td style="padding: 8px;">{chains}</td></tr>
            </table>
            <h3 style="color: #e5e7eb;">What Happened</h3>
            <p>{explanation.what_happened[:500]}</p>
            {actions_html}
            <hr style="border-color: #2a2a4a; margin: 16px 0;">
            <a href="{self.dashboard_url}/incidents/{incident.id}" style="color: #3B82F6;">View Full Incident</a>
            <p style="font-size: 12px; color: #6b7280; margin-top: 16px;">This alert was generated by Sentinel3 XDR. Do not reply to this email.</p>
        </div>
        </body></html>
        """

    # ── Dispatch ───────────────────────────────────────────────────

    async def _send(self, subject: str, html_body: str):
        """Route to SMTP or SendGrid."""
        if not self.to_emails:
            logger.info("email_would_send", subject=subject, reason="no recipients configured")
            return

        if self.provider == "sendgrid":
            await self._send_sendgrid(subject, html_body)
        else:
            await self._send_smtp(subject, html_body)

    async def _send_smtp(self, subject: str, html_body: str):
        """Send via SMTP using aiosmtplib."""
        try:
            import aiosmtplib
        except ImportError:
            logger.warning("aiosmtplib_not_installed")
            return

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.from_email
        msg["To"] = ", ".join(self.to_emails)
        msg.attach(MIMEText(html_body, "html"))

        try:
            await aiosmtplib.send(
                msg,
                hostname=self.smtp_host,
                port=self.smtp_port,
                username=self.smtp_user,
                password=self.smtp_password,
                use_tls=self.smtp_use_tls,
            )
            logger.info("email_alert_sent_smtp", to=self.to_emails, subject=subject)
        except Exception as e:
            logger.error("email_alert_failed_smtp", error=str(e))

    async def _send_sendgrid(self, subject: str, html_body: str):
        """Send via SendGrid HTTP API."""
        try:
            import httpx
        except ImportError:
            logger.warning("httpx_not_installed")
            return

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    "https://api.sendgrid.com/v3/mail/send",
                    headers={
                        "Authorization": f"Bearer {self.sendgrid_api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "personalizations": [{"to": [{"email": e} for e in self.to_emails]}],
                        "from": {"email": self.from_email},
                        "subject": subject,
                        "content": [{"type": "text/html", "value": html_body}],
                    },
                    timeout=10,
                )
                if resp.status_code in (200, 202):
                    logger.info("email_alert_sent_sendgrid", to=self.to_emails)
                else:
                    logger.error(
                        "email_alert_failed_sendgrid",
                        status=resp.status_code,
                        body=resp.text[:200],
                    )
        except Exception as e:
            logger.error("email_alert_failed_sendgrid", error=str(e))
