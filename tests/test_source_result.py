from hash_searcher.models import BazaarReport, SourceResult


def test_the_three_states_are_distinguishable():
    """The distinction every extractor in Phase 4 was built around, expressed
    once instead of six times with a seventh that could not."""
    never_asked = SourceResult()
    failed = SourceResult(error="MalwareBazaar API Error 500", queried=True)
    answered = SourceResult(value=BazaarReport(found=False), queried=True)

    assert not never_asked.queried and never_asked.error is None
    assert failed.queried and not failed.ok
    assert answered.ok and answered.value.found is False


def test_ok_is_false_for_a_result_nobody_asked_for():
    """The trap this type exists to close: `not result.error` was true for
    both 'it worked' and 'we never called it'."""
    assert SourceResult().ok is False
