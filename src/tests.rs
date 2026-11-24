use super::*;
use actix_web::{http::header, test, HttpResponse};
use std::path::PathBuf;

#[actix_web::test]
async fn security_headers_are_set() {
    let app = test::init_service(
        App::new()
            .wrap(security_headers())
            .route("/", web::get().to(|| async { HttpResponse::Ok().finish() })),
    )
    .await;
    let response = test::call_service(&app, test::TestRequest::get().uri("/").to_request()).await;
    assert_eq!(response.headers().get("X-Frame-Options").unwrap(), "DENY");
    assert!(response
        .headers()
        .get("Content-Security-Policy")
        .unwrap()
        .to_str()
        .unwrap()
        .contains("frame-ancestors 'none'"));
}

// Reserve a new cache directory so tests never overwrite existing cached images.
struct TestCache(PathBuf);

impl Drop for TestCache {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[actix_web::test]
async fn fresh_and_cached_images_have_matching_content_types() {
    fs::create_dir_all(".cache/1").unwrap();
    let (width, cache) = (1..=3000)
        .find_map(|width| {
            let path = PathBuf::from(format!(".cache/1/{width}"));
            fs::create_dir(&path).ok().map(|_| (width, TestCache(path)))
        })
        .expect("a free cache directory for the test");
    let height = 2;
    let cache_path = cache.0.join(height.to_string());
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(1u32))
            .app_data(web::Data::new(RateLimitingMiddleware::new()))
            .app_data(web::Data::new(GoogleAnalytics {
                client: reqwest::Client::new(),
                measurement_id: String::new(),
                api_secret: None,
            }))
            .service(resize_image),
    )
    .await;

    let uri = format!("/{width}/{height}");
    let mut fresh_body = None;
    for cached in [false, true] {
        assert_eq!(cache_path.exists(), cached);
        let response =
            test::call_service(&app, test::TestRequest::get().uri(&uri).to_request()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "image/png"
        );
        let body = test::read_body(response).await;
        assert!(body.starts_with(b"\x89PNG\r\n\x1a\n"));
        let decoded = image::load_from_memory(&body).unwrap();
        assert_eq!((decoded.width(), decoded.height()), (width, height));

        if let Some(ref fresh) = fresh_body {
            assert_eq!(&body, fresh);
        } else {
            // Cache writes run in a background task; wait for the complete file.
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    if tokio_fs::read(&cache_path).await.ok().as_deref() == Some(body.as_ref()) {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("fresh image was cached");
            fresh_body = Some(body);
        }
    }
}

fn test_ga() -> GoogleAnalytics {
    GoogleAnalytics {
        client: reqwest::Client::new(),
        measurement_id: String::new(),
        api_secret: None,
    }
}

fn info_for(req: test::TestRequest) -> RequestLogInfo {
    RequestLogInfo::from_request(&req.to_http_request())
}

macro_rules! resize_app {
    ($count:expr, $limiter:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($count as u32))
                .app_data(web::Data::new($limiter))
                .app_data(web::Data::new(test_ga()))
                .service(resize_image),
        )
        .await
    };
}

#[actix_web::test]
async fn security_headers_include_all_four() {
    let app = test::init_service(
        App::new()
            .wrap(security_headers())
            .route("/", web::get().to(|| async { HttpResponse::Ok().finish() })),
    )
    .await;
    let response = test::call_service(&app, test::TestRequest::get().uri("/").to_request()).await;
    let headers = response.headers();
    assert_eq!(headers.get("X-Content-Type-Options").unwrap(), "nosniff");
    assert_eq!(
        headers.get("Referrer-Policy").unwrap(),
        "strict-origin-when-cross-origin"
    );
    let csp = headers
        .get("Content-Security-Policy")
        .unwrap()
        .to_str()
        .unwrap();
    assert!(csp.contains("default-src 'self'"));
}

#[actix_web::test]
async fn resize_rejects_out_of_range_dimensions() {
    let app = resize_app!(1, RateLimitingMiddleware::new());
    for uri in ["/0/10", "/10/0", "/3001/10", "/10/3001"] {
        let response =
            test::call_service(&app, test::TestRequest::get().uri(uri).to_request()).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        let body: serde_json::Value = test::read_body_json(response).await;
        assert_eq!(body["error"], "Invalid image dimensions");
        assert_eq!(
            body["message"],
            "Width and height must be between 1 and 3000 pixels"
        );
    }
}

#[actix_web::test]
async fn resize_accepts_boundary_dimensions_before_cache_lookup() {
    let app = resize_app!(u32::MAX, RateLimitingMiddleware::new());
    let response = test::call_service(
        &app,
        test::TestRequest::get().uri("/3000/3000").to_request(),
    )
    .await;
    assert_ne!(response.status(), StatusCode::BAD_REQUEST);
}

#[actix_web::test]
async fn resize_returns_429_when_rate_limit_exhausted() {
    let limiter = RateLimitingMiddleware {
        limiter: Arc::new(RateLimiter::direct(Quota::per_hour(
            NonZeroU32::new(1).unwrap(),
        ))),
    };
    let app = resize_app!(1, limiter);
    let first = test::call_service(&app, test::TestRequest::get().uri("/0/0").to_request()).await;
    assert_eq!(first.status(), StatusCode::BAD_REQUEST);
    let second = test::call_service(&app, test::TestRequest::get().uri("/0/0").to_request()).await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    let body: serde_json::Value = test::read_body_json(second).await;
    assert_eq!(body["error"], "Too many requests");
    assert_eq!(body["retry_after"], "1 second");
}

#[actix_web::test]
async fn resize_returns_404_when_image_file_is_missing() {
    // Only a few dozen images exist, so a count of u32::MAX selects a missing file.
    let app = resize_app!(u32::MAX, RateLimitingMiddleware::new());
    let response =
        test::call_service(&app, test::TestRequest::get().uri("/5/5").to_request()).await;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    assert_eq!(test::read_body(response).await, "Image not found");
}

#[actix_web::test]
async fn health_check_status_matches_body() {
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(SystemMonitor::new()))
            .service(health_check),
    )
    .await;
    let response =
        test::call_service(&app, test::TestRequest::get().uri("/health").to_request()).await;
    let status = response.status();
    let body: serde_json::Value = test::read_body_json(response).await;
    match body["status"].as_str().unwrap() {
        "healthy" => assert_eq!(status, StatusCode::OK),
        "unhealthy" => assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE),
        other => panic!("unexpected status {other}"),
    }
    for key in [
        "memory_usage_percent",
        "total_memory_kb",
        "used_memory_kb",
        "cpu_usage_percent",
    ] {
        assert!(body["metrics"].get(key).is_some(), "missing {key}");
    }
    assert!(body["timestamp"].is_string());
}

#[actix_web::test]
async fn system_monitor_refreshes_after_one_second() {
    let monitor = SystemMonitor::new();
    let stale = Instant::now() - Duration::from_secs(2);
    *monitor.last_update.lock().await = stale;
    let metrics = monitor.get_health_metrics().await;
    assert!(metrics["metrics"]["total_memory_kb"].as_u64().unwrap() > 0);
    assert!(*monitor.last_update.lock().await > stale);
}

#[actix_web::test]
async fn request_info_defaults_without_headers() {
    let info = info_for(test::TestRequest::default());
    assert_eq!(info.user_agent, "unknown");
    assert_eq!(info.referer, None);
    assert_eq!(info.referer_domain, None);
    assert_eq!(info.ip, "unknown");
}

#[actix_web::test]
async fn request_info_ip_fallback_chain() {
    let info = info_for(test::TestRequest::default().insert_header(("X-Real-IP", "1.1.1.1")));
    assert_eq!(info.ip, "1.1.1.1");
    assert_eq!(info.x_real_ip.as_deref(), Some("1.1.1.1"));

    let info =
        info_for(test::TestRequest::default().insert_header(("CF-Connecting-IP", "2.2.2.2")));
    assert_eq!(info.ip, "2.2.2.2");
    assert_eq!(info.cf_connecting_ip.as_deref(), Some("2.2.2.2"));

    let info = info_for(
        test::TestRequest::default().insert_header(("X-Forwarded-For", "3.3.3.3, 4.4.4.4")),
    );
    assert_eq!(info.ip, "3.3.3.3");
    assert_eq!(info.x_forwarded_for.as_deref(), Some("3.3.3.3, 4.4.4.4"));
}

#[actix_web::test]
async fn request_info_parses_headers_and_referer() {
    let info = info_for(
        test::TestRequest::get()
            .uri("/10/20")
            .insert_header(("Referer", "https://example.com/page?x=1"))
            .insert_header(("User-Agent", "agent/1.0"))
            .insert_header(("Accept-Language", "en-GB,en;q=0.9")),
    );
    assert_eq!(info.referer_domain.as_deref(), Some("example.com"));
    assert_eq!(info.user_agent, "agent/1.0");
    assert_eq!(info.accept_language.as_deref(), Some("en-GB,en;q=0.9"));
    assert_eq!(info.method, "GET");
    assert_eq!(info.uri, "/10/20");

    let info = info_for(test::TestRequest::default().insert_header(("Referer", "not a url")));
    assert_eq!(info.referer.as_deref(), Some("not a url"));
    assert_eq!(info.referer_domain, None);
}

#[actix_web::test]
async fn logging_functions_accept_fully_populated_request() {
    let info = info_for(
        test::TestRequest::default()
            .insert_header(("X-Real-IP", "1.1.1.1"))
            .insert_header(("CF-Connecting-IP", "2.2.2.2"))
            .insert_header(("X-Forwarded-For", "3.3.3.3"))
            .insert_header(("Referer", "https://example.com/"))
            .insert_header(("Accept-Language", "en")),
    );
    info.log_request("extra");
    info.log_rate_limit();
    info.log_error("kind", "details");
}

#[actix_web::test]
async fn analytics_without_secret_returns_early() {
    let info = info_for(test::TestRequest::default());
    test_ga().track_image_request(&info, 1, 1, false, 1.0).await;
}

#[actix_web::test]
async fn analytics_with_secret_dispatches_event_to_google() {
    use tokio::io::AsyncReadExt;
    // A local proxy catches the request, so nothing leaves the machine.
    let proxy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_url = format!("http://{}", proxy.local_addr().unwrap());
    let ga = GoogleAnalytics {
        client: reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(proxy_url).unwrap())
            .build()
            .unwrap(),
        measurement_id: "test".to_string(),
        api_secret: Some("secret".to_string()),
    };
    let info = info_for(test::TestRequest::default());
    ga.track_image_request(&info, 1, 1, true, 1.0).await;

    let (mut conn, _) = tokio::time::timeout(Duration::from_secs(5), proxy.accept())
        .await
        .expect("analytics request reached the proxy")
        .unwrap();
    let mut buf = [0u8; 256];
    let n = conn.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("CONNECT www.google-analytics.com:443"));
}

#[actix_web::test]
async fn md5_hash_is_deterministic_and_input_sensitive() {
    assert_eq!(md5_hash("1.2.3.4"), md5_hash("1.2.3.4"));
    assert_ne!(md5_hash("1.2.3.4"), md5_hash("1.2.3.5"));
}

#[actix_web::test]
async fn count_images_counts_jpeg_and_jpg_case_insensitively() {
    let dir = std::env::temp_dir().join(format!("placedog-count-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    for name in ["a.jpeg", "b.JPG", "c.png", "d"] {
        fs::write(dir.join(name), b"").unwrap();
    }
    let count = count_images(dir.to_str().unwrap());
    fs::remove_dir_all(&dir).unwrap();
    assert_eq!(count, 2);
}

#[actix_web::test]
async fn count_images_returns_zero_for_missing_directory() {
    assert_eq!(count_images("./does-not-exist"), 0);
}

#[actix_web::test]
async fn configured_app_serves_routes_with_security_headers() {
    let app = test::init_service(
        App::new()
            .configure(|cfg| {
                configure_app(
                    cfg,
                    u32::MAX,
                    web::Data::new(SystemMonitor::new()),
                    web::Data::new(RateLimitingMiddleware::new()),
                    web::Data::new(test_ga()),
                )
            })
            .wrap(security_headers()),
    )
    .await;

    let health =
        test::call_service(&app, test::TestRequest::get().uri("/health").to_request()).await;
    assert!(health.headers().contains_key("X-Frame-Options"));
    assert!(health.status().is_success() || health.status() == StatusCode::SERVICE_UNAVAILABLE);

    let index = test::call_service(&app, test::TestRequest::get().uri("/").to_request()).await;
    assert_eq!(index.status(), StatusCode::OK);

    let missing = test::call_service(&app, test::TestRequest::get().uri("/5/5").to_request()).await;
    assert_eq!(missing.status(), StatusCode::NOT_FOUND);
}
