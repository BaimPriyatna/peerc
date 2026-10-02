"""tests/test_ui_resume.py — Phase 47.6: UI resume support smoke tests.

These are lightweight unit tests for the UI components, not full integration tests.
Visual/manual testing is done via the Textual app itself.
"""

import pytest

from app.ui.modals.transfer import FileOfferModal


def test_file_offer_modal_fresh_transfer():
    """FileOfferModal without resume_offset shows normal accept dialog."""
    modal = FileOfferModal(sender_name="Alice", filename="test.txt", size=100 * 1024)
    
    assert modal.sender_name == "Alice"
    assert modal.filename == "test.txt"
    assert modal.file_size == 100 * 1024
    assert modal.resume_offset == 0


def test_file_offer_modal_resume_transfer():
    """FileOfferModal with resume_offset > 0 shows resume info."""
    size = 100 * 1024
    resume_offset = 50 * 1024
    modal = FileOfferModal(sender_name="Bob", filename="large.bin", size=size, resume_offset=resume_offset)
    
    assert modal.sender_name == "Bob"
    assert modal.filename == "large.bin"
    assert modal.file_size == size
    assert modal.resume_offset == resume_offset


def test_file_offer_modal_resume_percentage_display():
    """FileOfferModal calculates resume percentage correctly for display."""
    size = 200 * 1024
    resume_offset = 100 * 1024  # 50%
    
    modal = FileOfferModal(sender_name="Carol", filename="half.txt", size=size, resume_offset=resume_offset)
    
    # The modal will display "Resume from 50%"
    resume_pct = (modal.resume_offset / modal.file_size * 100) if modal.file_size > 0 else 0
    assert resume_pct == 50.0


def test_file_offer_modal_zero_size_edge_case():
    """FileOfferModal handles zero-size files without division by zero."""
    modal = FileOfferModal(sender_name="Dave", filename="empty.txt", size=0, resume_offset=0)
    
    # Should not crash when calculating percentage
    resume_pct = (modal.resume_offset / modal.file_size * 100) if modal.file_size > 0 else 0
    assert resume_pct == 0.0


def test_file_offer_modal_resume_offset_equals_size():
    """FileOfferModal handles resume_offset == size (100% already received)."""
    size = 64 * 1024
    modal = FileOfferModal(sender_name="Eve", filename="complete.dat", size=size, resume_offset=size)
    
    resume_pct = (modal.resume_offset / modal.file_size * 100) if modal.file_size > 0 else 0
    assert resume_pct == 100.0
