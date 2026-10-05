"""
Tests for pdf_export.py — verifies real, valid PDF bytes are produced,
not just that the function runs without error.
"""
import pdf_export


def test_generates_valid_pdf_header():
    pdf_bytes = pdf_export.generate_report_pdf("Test report content.")
    assert pdf_bytes[:4] == b"%PDF"


def test_handles_multi_paragraph_text():
    text = "First paragraph.\n\nSecond paragraph.\n\nThird paragraph."
    pdf_bytes = pdf_export.generate_report_pdf(text)
    assert len(pdf_bytes) > 500


def test_handles_unicode_characters_without_crashing():
    # AI-generated text often contains smart quotes/em dashes that aren't
    # in Helvetica's base font — must not crash, even if characters get
    # substituted.
    text = "Here's a \u201csmart quote\u201d and an em dash \u2014 test."
    pdf_bytes = pdf_export.generate_report_pdf(text)
    assert pdf_bytes[:4] == b"%PDF"


def test_empty_report_does_not_crash():
    pdf_bytes = pdf_export.generate_report_pdf("")
    assert pdf_bytes[:4] == b"%PDF"
