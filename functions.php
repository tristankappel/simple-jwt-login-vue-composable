// Konstanten definieren
define('ALLOWED_ORIGINS', [
    'https://domain1.xyz',
    'https://domain2.xyz',
]);

define('COOKIE_EXPIRY', 60 * 60 * 24 * 14); // 14 Tage

// Gemeinsame Header-Funktion
function set_cors_headers() {
    if (isset($_SERVER['HTTP_ORIGIN']) && in_array($_SERVER['HTTP_ORIGIN'], ALLOWED_ORIGINS)) {
        header('Access-Control-Allow-Origin: ' . $_SERVER['HTTP_ORIGIN']);
    }

    header('Access-Control-Allow-Credentials: true');
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS, PUT');
    header('Access-Control-Allow-Headers: Origin, Content-Type, Accept, Authorization, X-Requested-With, X-CSRF-Token');
}

// Initiale CORS Behandlung + Preflight
add_action('init', function () {
    set_cors_headers();

    if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
        status_header(200);
        exit;
    }
}, 0);

// REST API CORS
add_filter('rest_pre_serve_request', function ($served, $result, $request, $server) {
    set_cors_headers();
    return $served;
}, 10, 4);

// Zusätzliche Daten nach Authentifizierung zurückgeben
add_filter('simple_jwt_login_response_auth_user', function ($response, $user) {
    $response['wp_user_id'] = $user->ID;
    $response['wp_user_role'] = $user->roles[0];
    return $response;
}, 10, 2);

// Set Cookie Endpoint
add_action('rest_api_init', function () {
    register_rest_route('cookiesetter/v1', '/set-cookie', [
        'methods' => 'POST',
        'permission_callback' => '__return_true',
        'callback' => function (WP_REST_Request $request) {
            $token = $request->get_param('token');

            if (!$token) {
                return new WP_Error('no_token', 'Token fehlt', ['status' => 400]);
            }

            setcookie('simple-jwt-login-token', $token, [
                'expires' => time() + COOKIE_EXPIRY,
                'path' => '/',
                'secure' => true,
                'httponly' => true,
                'samesite' => 'None',
            ]);

            $csrfToken = bin2hex(random_bytes(32));

            setcookie('csrf-token', $csrfToken, [
                'expires' => time() + COOKIE_EXPIRY,
                'path' => '/',
                'secure' => true,
                'httponly' => false,
                'samesite' => 'None',
            ]);

            return ['success' => true, 'csrfToken' => $csrfToken];
        },
    ]);
});

// Remove Cookie Endpoint
add_action('rest_api_init', function () {
    register_rest_route('cookiesetter/v1', '/remove-cookie', [
        'methods' => 'POST',
        'permission_callback' => '__return_true',
        'callback' => function (WP_REST_Request $request) {
            setcookie('simple-jwt-login-token', '', [
                'expires' => time() - COOKIE_EXPIRY,
                'path' => '/',
                'secure' => true,
                'httponly' => true,
                'samesite' => 'None',
            ]);

            setcookie('csrf-token', '', [
                'expires' => time() - COOKIE_EXPIRY,
                'path' => '/',
                'secure' => true,
                'httponly' => false,
                'samesite' => 'None',
            ]);

            return new WP_REST_Response(['message' => 'Logged out'], 200);
        },
    ]);
});

// CSRF-Schutz Middleware
add_filter('rest_request_before_callbacks', function ($response, $handler, $request) {
    $method = $request->get_method();
    $route = $request->get_route();

    $exemptRoutes = [
        '/simple-jwt-login/v1/auth',
        '/cookiesetter/v1/set-cookie',
        '/cookiesetter/v1/remove-cookie',
				'/simple-jwt-login/v1/users'
    ];

    if (in_array($route, $exemptRoutes)) {
        return null;
    }

    if (in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'])) {
        $csrfHeader = $request->get_header('X-CSRF-Token') ?: $request->get_header('x-csrf-token');
        $csrfCookie = $_COOKIE['csrf-token'] ?? null;

        if (!$csrfHeader || !$csrfCookie || $csrfHeader !== $csrfCookie) {
            return new WP_Error('csrf_mismatch', 'Ungültiger CSRF-Token', ['status' => 403]);
        }
    }

    return null;
}, 10, 3);
