use trace_store::ExpertTraceEvent;

#[test]
fn legacy_apex_shape_remains_accepted_by_trace_store() {
    let json = include_str!("apex-event.fixture.json");
    let event: ExpertTraceEvent = serde_json::from_str(json).unwrap();
    event.validate().unwrap();
}
