use trace_store::ExpertTraceEvent;

#[test]
fn generated_shape_is_accepted_by_apex_trace_store() {
    let json = include_str!("apex-event.fixture.json");
    let event: ExpertTraceEvent = serde_json::from_str(json).unwrap();
    event.validate().unwrap();
}
