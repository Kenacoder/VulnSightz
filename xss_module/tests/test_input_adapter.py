from xss.input_adapter import InputAdapter


def test_deduplicate_equivalent_points(sample_crawl_map):
    # Add duplicate endpoint
    sample_crawl_map["endpoints"] = [
        {
            "url": "http://127.0.0.1:5001/reflect",
            "method": "GET",
            "params": [
                {"name": "q", "value": "", "source": "query", "input_type": "text"}
            ],
        }
    ]
    adapter = InputAdapter()
    points = adapter.extract_input_points(sample_crawl_map)
    keys = [p.key for p in points]
    assert len(keys) == len(set(keys))


def test_post_form_fields_extracted():
    data = {
        "version": "1.0",
        "target": "http://127.0.0.1:5001",
        "pages": [],
        "forms": [
            {
                "action": "http://127.0.0.1:5001/comment",
                "method": "POST",
                "enctype": "application/x-www-form-urlencoded",
                "fields": [
                    {"name": "body", "value": "", "input_type": "textarea"},
                    {"name": "submit", "value": "Post", "input_type": "submit"},
                ],
                "renders_to": ["http://127.0.0.1:5001/comments"],
            }
        ],
    }
    points = InputAdapter().extract_input_points(data)
    assert len(points) == 1
    assert points[0].parameter == "body"
    assert points[0].method == "POST"
    assert points[0].renders_to == ("http://127.0.0.1:5001/comments",)


def test_invalid_crawl_map_raises():
    adapter = InputAdapter()
    try:
        adapter.load_data({"pages": []})
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "invalid crawl_map" in str(exc)
