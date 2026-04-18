"""
title: Prisma AIRS SDK Enforcement (Block, Mask & Detailed Reporting)
author: Gemini
version: 7.5
requirements: pan-aisecurity
"""

import aisecurity
import logging
import json
from aisecurity.scan.inline.scanner import Scanner
from aisecurity.generated_openapi_client.models.ai_profile import AiProfile
from aisecurity.scan.models.content import Content
from typing import Awaitable, Callable, Optional
from pydantic import BaseModel, Field

# Initialize logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

class Filter:
    class Valves(BaseModel):
        PRISMA_API_KEY: str = Field(default="", description="Your x-pan-token API Key")
        AI_PROFILE_NAME: str = Field(default="ark-sec-profile", description="AI Security Profile name")
        SHOW_ALLOWED_REPORT: bool = Field(default=True, description="Show diagnostic report even for allowed traffic")

    def __init__(self):
        self.valves = self.Valves()

    # Field mappings matching the Prisma AIRS API schema
    PROMPT_FIELD_MAP = {
        "injection": "Prompt Injection",
        "agent": "Agent System Abuse",
        "dlp": "Sensitive Data (DLP)",
        "toxic_content": "Toxic Content",
        "malicious_code": "Malicious Code",
        "url_cats": "Unsafe URL",
    }

    RESPONSE_FIELD_MAP = {
        "dlp": "Sensitive Data (DLP)",
        "toxic_content": "Toxic Content",
        "malicious_code": "Malicious Code",
        "url_cats": "Unsafe URL",
        "db_security": "Database Security Risk",
        "ungrounded": "Hallucination/Ungrounded",
    }

    def get_risk_labels(self, detection_data: dict, details: dict = None, field_map: dict = None) -> str:
        """Maps detection flags to human-readable labels."""
        if field_map is None: field_map = self.PROMPT_FIELD_MAP
        risks = []
        for key, label in field_map.items():
            if detection_data.get(key):
                if key == "toxic_content" and details:
                    cats = details.get("toxic_content_details", {}).get("toxic_categories", [])
                    if cats: label = f"Toxic Content ({', '.join(cats)})"
                risks.append(label)
        return ", ".join(risks) if risks else "None Detected"

    def get_dlp_summary(self, masked_data: dict) -> str:
        """Extracts DLP patterns and hit counts."""
        pattern_detections = masked_data.get("pattern_detections", [])
        if not pattern_detections: return ""
        counts = {}
        for detection in pattern_detections:
            pattern = detection.get("pattern", "Unknown")
            hits = len(detection.get("locations", []))
            counts[pattern] = counts.get(pattern, 0) + hits
        return ", ".join(f"{name} ({hits} hit{'s' if hits != 1 else ''})" for name, hits in counts.items())

    def generate_report(self, result, stage: str = "REQUEST") -> str:
        """Generates the standardized Prisma Diagnostic Report."""
        res_dict = result.to_dict() if hasattr(result, 'to_dict') else {}
        
        # Risk Mapping
        p_report = self.get_risk_labels(res_dict.get("prompt_detected", {}), res_dict.get("prompt_detection_details", {}), self.PROMPT_FIELD_MAP)
        r_report = self.get_risk_labels(res_dict.get("response_detected", {}), res_dict.get("response_detection_details", {}), self.RESPONSE_FIELD_MAP)
        
        # DLP Info
        masked_info = res_dict.get("response_masked_data", {})
        dlp_summary = self.get_dlp_summary(masked_info)
        dlp_line = f"\n[DLP] Patterns: {dlp_summary}" if dlp_summary else ""

        verdict = "BLOCK/RISK DETECTED" if result.action == "block" else "ALLOWED/CLEAN"
        api_category = res_dict.get("category", "n/a")

        report = (
            f"\n\n---\n"
            f"🛡️ **PRISMA AIRS SECURITY REPORT ({stage})**\n"
            f"Overall Verdict: **{verdict}** — API Category: `{api_category}`\n"
            f"Scan ID: `{result.scan_id}` | Report ID: `R{result.scan_id}`\n\n"
            f"[1] Prompt Detected (Input): {p_report}\n"
            f"[2] Response Detected (Output): {r_report}"
            f"{dlp_line}\n\n"
            f"---  \n"
            f"*Scripted for demo purpose only - by @PacketCraft 🐙*"
        )
        return report

    async def inlet(self, body: dict, __user__: dict = None, __event_emitter__: Callable[[dict], Awaitable[None]] = None) -> dict:
        """Stage 1: Protect the LLM by blocking malicious prompts."""
        user_email = __user__.get("email", "unknown-user") if __user__ else "unknown-user"
        if __event_emitter__:
            await __event_emitter__({"type": "status", "data": {"description": "🛡️ Prisma AIRS: Shielding Prompt...", "done": False}})

        user_prompt = body.get("messages", [])[-1].get("content", "")
        
        try:
            aisecurity.init(api_key=self.valves.PRISMA_API_KEY.strip())
            scanner = Scanner()
            profile = AiProfile(profile_name=self.valves.AI_PROFILE_NAME.strip())
            result = scanner.sync_scan(ai_profile=profile, content=Content(prompt=user_prompt))
            
            diag_report = self.generate_report(result, stage="REQUEST")

            if result.action == "block":
                if __event_emitter__:
                    await __event_emitter__({"type": "status", "data": {"description": "🚨 BLOCK: Malicious Prompt", "done": True}})
                # Exception message now includes the diagnostic report for a detailed block screen
                raise Exception(f"Malicious input detected.{diag_report}")
            
            elif self.valves.SHOW_ALLOWED_REPORT:
                # Optionally log allowed request diagnostics to console
                logger.info(f"AIRS-SDK Request Allowed: {result.scan_id}")

        except Exception as e:
            if "Malicious input detected" in str(e): raise e
            logger.error(f"AIRS-SDK Inlet Error: {str(e)}")

        return body

    async def outlet(self, body: dict, __user__: dict = None, __event_emitter__: Callable[[dict], Awaitable[None]] = None) -> dict:
        """Stage 2: Sanitize Response - Block threats and MASK sensitive data (DLP)."""
        user_email = __user__.get("email", "unknown-user") if __user__ else "unknown-user"
        if __event_emitter__:
            await __event_emitter__({"type": "status", "data": {"description": "🛡️ Prisma AIRS: Sanitizing Response...", "done": False}})

        messages = body.get("messages", [])
        ai_res = messages[-1].get("content", "")
        user_prompt = messages[-2].get("content", "") if len(messages) > 1 else ""

        try:
            aisecurity.init(api_key=self.valves.PRISMA_API_KEY.strip())
            scanner = Scanner()
            profile = AiProfile(profile_name=self.valves.AI_PROFILE_NAME.strip())
            result = scanner.sync_scan(ai_profile=profile, content=Content(prompt=user_prompt, response=ai_res))
            
            res_dict = result.to_dict() if hasattr(result, 'to_dict') else {}
            masked_info = res_dict.get("response_masked_data", {})
            has_dlp_hits = len(masked_info.get("pattern_detections", [])) > 0
            
            diag_report = self.generate_report(result, stage="RESPONSE")

            # 1. HARD BLOCK: Malicious content (Toxic, Code, etc.) — takes priority over DLP masking
            if result.action == "block":
                body["messages"][-1]["content"] = f"🚨 **Security Block**: Dangerous content detected and removed.{diag_report}"
                status = "🚨 Response Blocked"
            
            # 2. MASKING: Sensitive data
            elif has_dlp_hits:
                masked_text = masked_info.get("masked_response", " [REDACTED BY SECURITY POLICY] ")
                body["messages"][-1]["content"] = f"{masked_text}{diag_report}"
                status = "🔐 Response Masked"
            
            # 3. ALLOWED: Clean traffic
            else:
                if self.valves.SHOW_ALLOWED_REPORT:
                    body["messages"][-1]["content"] += diag_report
                status = "✅ Response Verified"

        except Exception as e:
            logger.error(f"AIRS-SDK Outlet Error: {str(e)}")
            status = f"❌ Outlet Error: {e}"

        if __event_emitter__:
            await __event_emitter__({"type": "status", "data": {"description": f"Prisma {status}", "done": True}})
        
        return body
