"""
ThreatPulse — Ingestion Scheduler
Runs all fetchers on configurable intervals using APScheduler.
Also exposes a manual trigger for immediate on-demand polling.
"""

import asyncio
from datetime import datetime
from typing import Optional
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from rich.console import Console

import config
from ingest.nvd import NVDFetcher
from ingest.cisa import CISAKEVFetcher, CISAAdvisoriesFetcher, CISAICSFetcher
from ingest.rss_feeds import build_all_vendor_fetchers
from ingest.threat_intel import URLHausFetcher, OTXFetcher, NPMAdvisoryFetcher, PyPIAdvisoryFetcher

console = Console()
scheduler: Optional[AsyncIOScheduler] = None

# Registry: feed_id → fetcher instance
_fetchers: dict = {}


def _build_fetchers() -> dict:
    fetchers = {}

    # Core feeds
    for f in [
        NVDFetcher(lookback_hours=26),  # slightly more than poll interval to avoid gaps
        CISAKEVFetcher(),
        CISAAdvisoriesFetcher(),
        CISAICSFetcher(),
        URLHausFetcher(),
        OTXFetcher(),
        NPMAdvisoryFetcher(),
        PyPIAdvisoryFetcher(),
    ]:
        fetchers[f.feed_id] = f

    # Vendor RSS feeds
    for f in build_all_vendor_fetchers():
        fetchers[f.feed_id] = f

    return fetchers


async def _run_fetcher(feed_id: str):
    fetcher = _fetchers.get(feed_id)
    if not fetcher:
        console.print(f"[red]No fetcher found for feed_id={feed_id}[/]")
        return
    try:
        await fetcher.run()
    except Exception as e:
        console.print(f"[red]Scheduler error for {feed_id}: {e}[/]")


async def run_all() -> dict:
    """Run all fetchers immediately and return counts."""
    results = {}
    for feed_id, fetcher in _fetchers.items():
        try:
            count = await fetcher.run()
            results[feed_id] = count
        except Exception as e:
            console.print(f"[red]Error running {feed_id}: {e}[/]")
            results[feed_id] = -1
    return results


async def run_feed(feed_id: str) -> int:
    """Run a single fetcher by ID. Used by API for on-demand refresh."""
    fetcher = _fetchers.get(feed_id)
    if not fetcher:
        return -1
    return await fetcher.run()


def get_feed_ids() -> list[str]:
    return list(_fetchers.keys())


def start_scheduler():
    global scheduler, _fetchers
    _fetchers = _build_fetchers()
    scheduler = AsyncIOScheduler()

    # Group fetchers by interval
    fast_feeds = [f for f in _fetchers.values() if f.poll_interval <= config.POLL_FAST]
    slow_feeds = [f for f in _fetchers.values() if f.poll_interval > config.POLL_FAST]

    # Fast polling group (KEV, NVD, URLhaus)
    for fetcher in fast_feeds:
        scheduler.add_job(
            _run_fetcher,
            trigger=IntervalTrigger(minutes=fetcher.poll_interval),
            args=[fetcher.feed_id],
            id=f"poll_{fetcher.feed_id}",
            name=fetcher.feed_label,
            replace_existing=True,
            max_instances=1,
            misfire_grace_time=60,
        )

    # Slow polling group (vendor RSS, threat intel)
    for fetcher in slow_feeds:
        scheduler.add_job(
            _run_fetcher,
            trigger=IntervalTrigger(minutes=fetcher.poll_interval),
            args=[fetcher.feed_id],
            id=f"poll_{fetcher.feed_id}",
            name=fetcher.feed_label,
            replace_existing=True,
            max_instances=1,
            misfire_grace_time=300,
        )

    # Daily cleanup job
    from db import database as db
    scheduler.add_job(
        db.purge_old_items,
        trigger=IntervalTrigger(hours=24),
        id="purge_old",
        name="Purge old items",
        replace_existing=True,
    )

    scheduler.start()
    console.print(
        f"[green]✓ Scheduler started[/] — "
        f"{len(fast_feeds)} fast feeds (every {config.POLL_FAST}m), "
        f"{len(slow_feeds)} slow feeds (every {config.POLL_SLOW}m)"
    )


def stop_scheduler():
    global scheduler
    if scheduler and scheduler.running:
        scheduler.shutdown(wait=False)
        scheduler = None
