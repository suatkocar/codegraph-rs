//! Framework-specific route and component resolution.
//!
//! Resolves framework patterns like Express route handlers, React component
//! references, and Django URL patterns into graph edges.

use std::collections::HashMap;

use crate::types::{CodeEdge, CodeNode, EdgeKind};

/// Resolve framework-specific patterns into additional edges.
pub fn resolve_framework_patterns(
    nodes_by_file: &HashMap<String, Vec<CodeNode>>,
    detected_frameworks: &[String],
) -> Vec<CodeEdge> {
    let mut edges = Vec::new();

    for framework in detected_frameworks {
        match framework.to_lowercase().as_str() {
            "react" | "next.js" => {
                edges.extend(resolve_react_components(nodes_by_file));
            }
            "express" => {
                edges.extend(resolve_express_routes(nodes_by_file));
            }
            "django" => {
                edges.extend(resolve_django_urls(nodes_by_file));
            }
            "rails" => {
                edges.extend(resolve_rails_routes(nodes_by_file));
            }
            "laravel" => {
                edges.extend(resolve_laravel_routes(nodes_by_file));
            }
            "spring boot" => {
                edges.extend(resolve_spring_boot_routes(nodes_by_file));
            }
            _ => {}
        }
    }

    edges
}

/// Resolve React component references.
///
/// When a PascalCase function or class name in one file matches a node name
/// in another file, create a References edge (component usage pattern).
fn resolve_react_components(nodes_by_file: &HashMap<String, Vec<CodeNode>>) -> Vec<CodeEdge> {
    let mut edges = Vec::new();

    // Build a global name->node lookup for PascalCase symbols (components)
    let mut component_index: HashMap<&str, Vec<&CodeNode>> = HashMap::new();
    for nodes in nodes_by_file.values() {
        for node in nodes {
            if is_pascal_case(&node.name) {
                component_index
                    .entry(node.name.as_str())
                    .or_default()
                    .push(node);
            }
        }
    }

    // For each file, look for PascalCase references to components in other files
    for (file_path, nodes) in nodes_by_file {
        for node in nodes {
            if !is_pascal_case(&node.name) {
                continue;
            }

            // Check if this component name exists in OTHER files
            if let Some(targets) = component_index.get(node.name.as_str()) {
                for &target in targets {
                    if target.file_path != *file_path && target.id != node.id {
                        edges.push(CodeEdge {
                            source: node.id.clone(),
                            target: target.id.clone(),
                            kind: EdgeKind::References,
                            file_path: file_path.clone(),
                            line: node.start_line,
                            metadata: Some(
                                [("framework".to_string(), "react".to_string())]
                                    .into_iter()
                                    .collect(),
                            ),
                        });
                    }
                }
            }
        }
    }

    edges
}

/// Resolve Express route handler references.
///
/// Looks for handler functions (named like route patterns) and creates
/// References edges from route-like nodes to their handler functions.
fn resolve_express_routes(nodes_by_file: &HashMap<String, Vec<CodeNode>>) -> Vec<CodeEdge> {
    let mut edges = Vec::new();

    // Build a global name->node lookup for all functions
    let mut function_index: HashMap<&str, Vec<&CodeNode>> = HashMap::new();
    for nodes in nodes_by_file.values() {
        for node in nodes {
            if node.kind == crate::types::NodeKind::Function
                || node.kind == crate::types::NodeKind::Method
            {
                function_index
                    .entry(node.name.as_str())
                    .or_default()
                    .push(node);
            }
        }
    }

    // Look for route handler registration patterns in function bodies.
    // Express patterns: app.get('/path', handler), router.post('/path', handler)
    let route_methods = ["get", "post", "put", "delete", "patch", "use"];

    for nodes in nodes_by_file.values() {
        for node in nodes {
            let body = match &node.body {
                Some(b) => b,
                None => continue,
            };

            for method in &route_methods {
                // Look for patterns like `.get('/path', handlerName)` in function bodies
                let pattern = format!(".{}(", method);
                if !body.contains(&pattern) {
                    continue;
                }

                // Extract handler names referenced after route method calls.
                // Look for identifiers that match known functions.
                for (fn_name, targets) in &function_index {
                    if body.contains(fn_name) && *fn_name != node.name.as_str() {
                        for &target in targets {
                            if target.id != node.id {
                                edges.push(CodeEdge {
                                    source: node.id.clone(),
                                    target: target.id.clone(),
                                    kind: EdgeKind::References,
                                    file_path: node.file_path.clone(),
                                    line: node.start_line,
                                    metadata: Some(
                                        [("framework".to_string(), "express".to_string())]
                                            .into_iter()
                                            .collect(),
                                    ),
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    edges
}

/// Resolve Django URL pattern references.
///
/// Looks for view function references in URL configuration patterns
/// and creates References edges to the view functions.
fn resolve_django_urls(nodes_by_file: &HashMap<String, Vec<CodeNode>>) -> Vec<CodeEdge> {
    let mut edges = Vec::new();

    // Build a global name->node lookup for all Python functions (views)
    let mut function_index: HashMap<&str, Vec<&CodeNode>> = HashMap::new();
    for nodes in nodes_by_file.values() {
        for node in nodes {
            if node.kind == crate::types::NodeKind::Function
                || node.kind == crate::types::NodeKind::Class
            {
                function_index
                    .entry(node.name.as_str())
                    .or_default()
                    .push(node);
            }
        }
    }

    // Look for URL configuration files (urls.py) that reference view functions
    for (file_path, nodes) in nodes_by_file {
        if !file_path.ends_with("urls.py") {
            continue;
        }

        for node in nodes {
            let body = match &node.body {
                Some(b) => b,
                None => continue,
            };

            // Django patterns: path('route/', views.handler_name) or url(r'^route/', handler)
            if !body.contains("path(") && !body.contains("url(") {
                continue;
            }

            // Check for references to known functions
            for (fn_name, targets) in &function_index {
                if body.contains(fn_name) && *fn_name != node.name.as_str() {
                    for &target in targets {
                        if target.file_path != *file_path {
                            edges.push(CodeEdge {
                                source: node.id.clone(),
                                target: target.id.clone(),
                                kind: EdgeKind::References,
                                file_path: file_path.clone(),
                                line: node.start_line,
                                metadata: Some(
                                    [("framework".to_string(), "django".to_string())]
                                        .into_iter()
                                        .collect(),
                                ),
                            });
                        }
                    }
                }
            }
        }
    }

    edges
}

/// Resolve Rails route-to-controller references.
///
/// Looks for route definitions in `routes.rb` files that reference controller
/// actions (e.g., `resources :users` or `get 'profile', to: 'users#show'`),
/// and creates References edges to matching controller methods.
fn resolve_rails_routes(nodes_by_file: &HashMap<String, Vec<CodeNode>>) -> Vec<CodeEdge> {
    let mut edges = Vec::new();

    // Build a lookup for all methods/functions (controller actions)
    let mut action_index: HashMap<&str, Vec<&CodeNode>> = HashMap::new();
    for nodes in nodes_by_file.values() {
        for node in nodes {
            if node.kind == crate::types::NodeKind::Method
                || node.kind == crate::types::NodeKind::Function
            {
                action_index
                    .entry(node.name.as_str())
                    .or_default()
                    .push(node);
            }
        }
    }

    // Scan route files for controller references
    for (file_path, nodes) in nodes_by_file {
        if !file_path.contains("routes.rb") && !file_path.ends_with("routes.rb") {
            continue;
        }

        for node in nodes {
            let body = match &node.body {
                Some(b) => b,
                None => continue,
            };

            // Rails route patterns: resources, get/post/put/delete with controller#action
            if !body.contains("resources")
                && !body.contains("get ")
                && !body.contains("post ")
                && !body.contains("root ")
            {
                continue;
            }

            for (action_name, targets) in &action_index {
                if body.contains(action_name) && *action_name != node.name.as_str() {
                    for &target in targets {
                        if target.file_path != *file_path {
                            edges.push(CodeEdge {
                                source: node.id.clone(),
                                target: target.id.clone(),
                                kind: EdgeKind::References,
                                file_path: file_path.clone(),
                                line: node.start_line,
                                metadata: Some(
                                    [("framework".to_string(), "rails".to_string())]
                                        .into_iter()
                                        .collect(),
                                ),
                            });
                        }
                    }
                }
            }
        }
    }

    edges
}

/// Resolve Laravel route-to-controller references.
///
/// Looks for route definitions in `routes/*.php` or `web.php`/`api.php` that
/// reference controller classes (e.g., `Route::get('/users', [UserController::class, 'index'])`),
/// and creates References edges to matching controller methods.
fn resolve_laravel_routes(nodes_by_file: &HashMap<String, Vec<CodeNode>>) -> Vec<CodeEdge> {
    let mut edges = Vec::new();

    // Build a lookup for all classes and methods (controllers and actions)
    let mut symbol_index: HashMap<&str, Vec<&CodeNode>> = HashMap::new();
    for nodes in nodes_by_file.values() {
        for node in nodes {
            if node.kind == crate::types::NodeKind::Class
                || node.kind == crate::types::NodeKind::Method
                || node.kind == crate::types::NodeKind::Function
            {
                symbol_index
                    .entry(node.name.as_str())
                    .or_default()
                    .push(node);
            }
        }
    }

    // Scan route files for controller references
    for (file_path, nodes) in nodes_by_file {
        let is_route_file = file_path.contains("routes/")
            || file_path.ends_with("web.php")
            || file_path.ends_with("api.php");
        if !is_route_file {
            continue;
        }

        for node in nodes {
            let body = match &node.body {
                Some(b) => b,
                None => continue,
            };

            // Laravel patterns: Route::get(), Route::post(), Route::resource()
            if !body.contains("Route::") {
                continue;
            }

            for (sym_name, targets) in &symbol_index {
                if body.contains(sym_name) && *sym_name != node.name.as_str() {
                    for &target in targets {
                        if target.file_path != *file_path {
                            edges.push(CodeEdge {
                                source: node.id.clone(),
                                target: target.id.clone(),
                                kind: EdgeKind::References,
                                file_path: file_path.clone(),
                                line: node.start_line,
                                metadata: Some(
                                    [("framework".to_string(), "laravel".to_string())]
                                        .into_iter()
                                        .collect(),
                                ),
                            });
                        }
                    }
                }
            }
        }
    }

    edges
}

/// Resolve Spring Boot annotation-based route references.
///
/// Looks for `@RequestMapping`, `@GetMapping`, `@PostMapping` etc. annotations
/// in controller classes, and creates References edges from annotated methods
/// to service classes they call.
fn resolve_spring_boot_routes(nodes_by_file: &HashMap<String, Vec<CodeNode>>) -> Vec<CodeEdge> {
    let mut edges = Vec::new();

    // Build a lookup for all classes/methods (services, repositories)
    let mut class_index: HashMap<&str, Vec<&CodeNode>> = HashMap::new();
    for nodes in nodes_by_file.values() {
        for node in nodes {
            if node.kind == crate::types::NodeKind::Class
                || node.kind == crate::types::NodeKind::Interface
            {
                class_index
                    .entry(node.name.as_str())
                    .or_default()
                    .push(node);
            }
        }
    }

    let mapping_annotations = [
        "@RequestMapping",
        "@GetMapping",
        "@PostMapping",
        "@PutMapping",
        "@DeleteMapping",
        "@PatchMapping",
        "@RestController",
        "@Controller",
    ];

    // Find controller classes (annotated with @Controller/@RestController)
    // and create edges to service classes they reference
    for nodes in nodes_by_file.values() {
        for node in nodes {
            let body = match &node.body {
                Some(b) => b,
                None => continue,
            };

            // Check if this node has Spring mapping annotations
            let has_mapping = mapping_annotations.iter().any(|ann| body.contains(ann));
            if !has_mapping {
                continue;
            }

            // Look for references to known classes (services injected via constructor/field)
            for (class_name, targets) in &class_index {
                if body.contains(class_name) && *class_name != node.name.as_str() {
                    for &target in targets {
                        if target.id != node.id {
                            edges.push(CodeEdge {
                                source: node.id.clone(),
                                target: target.id.clone(),
                                kind: EdgeKind::References,
                                file_path: node.file_path.clone(),
                                line: node.start_line,
                                metadata: Some(
                                    [("framework".to_string(), "spring".to_string())]
                                        .into_iter()
                                        .collect(),
                                ),
                            });
                        }
                    }
                }
            }
        }
    }

    edges
}

/// Check if a name follows PascalCase convention (used for React components).
fn is_pascal_case(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let first = name.chars().next().unwrap();
    // Must start with uppercase letter and contain at least one lowercase letter
    first.is_ascii_uppercase() && name.chars().any(|c| c.is_ascii_lowercase())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Language, NodeKind};

    fn make_node(id: &str, name: &str, file: &str, kind: NodeKind, body: Option<&str>) -> CodeNode {
        CodeNode {
            id: id.to_string(),
            name: name.to_string(),
            qualified_name: None,
            kind,
            file_path: file.to_string(),
            start_line: 1,
            end_line: 10,
            start_column: 0,
            end_column: 1,
            language: Language::TypeScript,
            body: body.map(|s| s.to_string()),
            documentation: None,
            exported: Some(true),
        }
    }

    // -- is_pascal_case -------------------------------------------------------

    #[test]
    fn pascal_case_detection() {
        assert!(is_pascal_case("MyComponent"));
        assert!(is_pascal_case("App"));
        assert!(is_pascal_case("UserProfile"));
        assert!(!is_pascal_case("myFunction"));
        assert!(!is_pascal_case("CONSTANT"));
        assert!(!is_pascal_case(""));
        assert!(!is_pascal_case("a"));
    }

    // -- React component resolution -------------------------------------------

    #[test]
    fn resolve_react_creates_cross_file_component_edges() {
        let mut nodes_by_file: HashMap<String, Vec<CodeNode>> = HashMap::new();

        // Header component defined in header.tsx
        let header = make_node(
            "class:header.tsx:Header:1",
            "Header",
            "header.tsx",
            NodeKind::Class,
            Some("export class Header {}"),
        );

        // App component uses Header (same name in another file)
        let app = make_node(
            "fn:app.tsx:Header:5",
            "Header",
            "app.tsx",
            NodeKind::Function,
            Some("function Header() {}"),
        );

        nodes_by_file.insert("header.tsx".to_string(), vec![header]);
        nodes_by_file.insert("app.tsx".to_string(), vec![app]);

        let frameworks = vec!["react".to_string()];
        let edges = resolve_framework_patterns(&nodes_by_file, &frameworks);

        // Should create cross-file References edges between same-named PascalCase symbols
        assert!(
            !edges.is_empty(),
            "Should create edges for same-named React components across files"
        );
        assert!(edges.iter().all(|e| e.kind == EdgeKind::References));
        assert!(edges
            .iter()
            .all(|e| e.metadata.as_ref().unwrap().get("framework").unwrap() == "react"));
    }

    #[test]
    fn react_skips_non_pascal_case() {
        let mut nodes_by_file: HashMap<String, Vec<CodeNode>> = HashMap::new();

        nodes_by_file.insert(
            "utils.ts".to_string(),
            vec![make_node(
                "fn:utils.ts:helper:1",
                "helper",
                "utils.ts",
                NodeKind::Function,
                None,
            )],
        );
        nodes_by_file.insert(
            "main.ts".to_string(),
            vec![make_node(
                "fn:main.ts:helper:1",
                "helper",
                "main.ts",
                NodeKind::Function,
                None,
            )],
        );

        let frameworks = vec!["react".to_string()];
        let edges = resolve_framework_patterns(&nodes_by_file, &frameworks);

        assert!(
            edges.is_empty(),
            "Should not create edges for non-PascalCase names"
        );
    }

    // -- Express route resolution ---------------------------------------------

    #[test]
    fn resolve_express_creates_route_handler_edges() {
        let mut nodes_by_file: HashMap<String, Vec<CodeNode>> = HashMap::new();

        let route_setup = make_node(
            "fn:routes.ts:setupRoutes:1",
            "setupRoutes",
            "routes.ts",
            NodeKind::Function,
            Some("function setupRoutes(app) { app.get('/users', listUsers); app.post('/users', createUser); }"),
        );
        let handler1 = make_node(
            "fn:handlers.ts:listUsers:1",
            "listUsers",
            "handlers.ts",
            NodeKind::Function,
            Some("function listUsers(req, res) {}"),
        );
        let handler2 = make_node(
            "fn:handlers.ts:createUser:10",
            "createUser",
            "handlers.ts",
            NodeKind::Function,
            Some("function createUser(req, res) {}"),
        );

        nodes_by_file.insert("routes.ts".to_string(), vec![route_setup]);
        nodes_by_file.insert("handlers.ts".to_string(), vec![handler1, handler2]);

        let frameworks = vec!["express".to_string()];
        let edges = resolve_framework_patterns(&nodes_by_file, &frameworks);

        assert!(
            edges.len() >= 2,
            "Should create edges for each handler reference, got {}",
            edges.len()
        );
        assert!(edges
            .iter()
            .any(|e| e.target == "fn:handlers.ts:listUsers:1"));
        assert!(edges
            .iter()
            .any(|e| e.target == "fn:handlers.ts:createUser:10"));
    }

    // -- Django URL resolution ------------------------------------------------

    #[test]
    fn resolve_django_creates_url_view_edges() {
        let mut nodes_by_file: HashMap<String, Vec<CodeNode>> = HashMap::new();

        let url_config = make_node(
            "fn:urls.py:urlpatterns:1",
            "urlpatterns",
            "urls.py",
            NodeKind::Variable,
            Some("urlpatterns = [path('users/', list_users), path('create/', create_user)]"),
        );
        let view1 = make_node(
            "fn:views.py:list_users:1",
            "list_users",
            "views.py",
            NodeKind::Function,
            Some("def list_users(request): pass"),
        );
        let view2 = make_node(
            "fn:views.py:create_user:10",
            "create_user",
            "views.py",
            NodeKind::Function,
            Some("def create_user(request): pass"),
        );

        nodes_by_file.insert("urls.py".to_string(), vec![url_config]);
        nodes_by_file.insert("views.py".to_string(), vec![view1, view2]);

        let frameworks = vec!["django".to_string()];
        let edges = resolve_framework_patterns(&nodes_by_file, &frameworks);

        assert!(
            edges.len() >= 2,
            "Should create edges for each view reference, got {}",
            edges.len()
        );
        assert!(edges.iter().any(|e| e.target == "fn:views.py:list_users:1"));
        assert!(edges
            .iter()
            .any(|e| e.target == "fn:views.py:create_user:10"));
    }

    // -- Rails route resolution -----------------------------------------------

    #[test]
    fn resolve_rails_creates_route_controller_edges() {
        let mut nodes_by_file: HashMap<String, Vec<CodeNode>> = HashMap::new();

        let route_config = make_node(
            "fn:config/routes.rb:draw:1",
            "draw",
            "config/routes.rb",
            NodeKind::Function,
            Some("Rails.application.routes.draw do\n  resources :users\n  get 'profile', to: 'users#show'\nend"),
        );
        let controller_action = make_node(
            "method:app/controllers/users_controller.rb:show:5",
            "show",
            "app/controllers/users_controller.rb",
            NodeKind::Method,
            Some("def show\n  @user = User.find(params[:id])\nend"),
        );

        nodes_by_file.insert("config/routes.rb".to_string(), vec![route_config]);
        nodes_by_file.insert(
            "app/controllers/users_controller.rb".to_string(),
            vec![controller_action],
        );

        let frameworks = vec!["rails".to_string()];
        let edges = resolve_framework_patterns(&nodes_by_file, &frameworks);

        assert!(
            !edges.is_empty(),
            "Should create edges for Rails route -> controller action"
        );
        assert!(edges
            .iter()
            .any(|e| e.target == "method:app/controllers/users_controller.rb:show:5"));
        assert!(edges
            .iter()
            .all(|e| e.metadata.as_ref().unwrap().get("framework").unwrap() == "rails"));
    }

    // -- Laravel route resolution ---------------------------------------------

    #[test]
    fn resolve_laravel_creates_route_controller_edges() {
        let mut nodes_by_file: HashMap<String, Vec<CodeNode>> = HashMap::new();

        let route_def = make_node(
            "fn:routes/web.php:routes:1",
            "routes",
            "routes/web.php",
            NodeKind::Function,
            Some("Route::get('/users', [UserController::class, 'index']);\nRoute::post('/users', [UserController::class, 'store']);"),
        );
        let controller = make_node(
            "class:app/Http/Controllers/UserController.php:UserController:1",
            "UserController",
            "app/Http/Controllers/UserController.php",
            NodeKind::Class,
            Some("class UserController extends Controller { public function index() {} }"),
        );

        nodes_by_file.insert("routes/web.php".to_string(), vec![route_def]);
        nodes_by_file.insert(
            "app/Http/Controllers/UserController.php".to_string(),
            vec![controller],
        );

        let frameworks = vec!["laravel".to_string()];
        let edges = resolve_framework_patterns(&nodes_by_file, &frameworks);

        assert!(
            !edges.is_empty(),
            "Should create edges for Laravel route -> controller"
        );
        assert!(edges
            .iter()
            .any(|e| e.target == "class:app/Http/Controllers/UserController.php:UserController:1"));
        assert!(edges
            .iter()
            .all(|e| e.metadata.as_ref().unwrap().get("framework").unwrap() == "laravel"));
    }

    // -- Spring Boot route resolution -----------------------------------------

    #[test]
    fn resolve_spring_boot_creates_controller_service_edges() {
        let mut nodes_by_file: HashMap<String, Vec<CodeNode>> = HashMap::new();

        let controller = make_node(
            "class:UserController.java:UserController:1",
            "UserController",
            "UserController.java",
            NodeKind::Class,
            Some("@RestController\n@RequestMapping(\"/api/users\")\npublic class UserController {\n    private final UserService userService;\n    @GetMapping\n    public List<User> list() { return userService.findAll(); }\n}"),
        );
        let service = make_node(
            "class:UserService.java:UserService:1",
            "UserService",
            "UserService.java",
            NodeKind::Class,
            Some("@Service\npublic class UserService { public List<User> findAll() { return repo.findAll(); } }"),
        );

        nodes_by_file.insert("UserController.java".to_string(), vec![controller]);
        nodes_by_file.insert("UserService.java".to_string(), vec![service]);

        let frameworks = vec!["spring boot".to_string()];
        let edges = resolve_framework_patterns(&nodes_by_file, &frameworks);

        assert!(
            !edges.is_empty(),
            "Should create edges for Spring controller -> service"
        );
        assert!(edges
            .iter()
            .any(|e| e.target == "class:UserService.java:UserService:1"));
        assert!(edges
            .iter()
            .all(|e| e.metadata.as_ref().unwrap().get("framework").unwrap() == "spring"));
    }

    // -- Framework dispatch ---------------------------------------------------

    #[test]
    fn unknown_framework_produces_no_edges() {
        let nodes_by_file: HashMap<String, Vec<CodeNode>> = HashMap::new();
        let frameworks = vec!["flask".to_string()];
        let edges = resolve_framework_patterns(&nodes_by_file, &frameworks);
        assert!(edges.is_empty());
    }

    #[test]
    fn no_frameworks_produces_no_edges() {
        let nodes_by_file: HashMap<String, Vec<CodeNode>> = HashMap::new();
        let frameworks: Vec<String> = vec![];
        let edges = resolve_framework_patterns(&nodes_by_file, &frameworks);
        assert!(edges.is_empty());
    }

    #[test]
    fn multiple_frameworks_combine_edges() {
        let mut nodes_by_file: HashMap<String, Vec<CodeNode>> = HashMap::new();

        // React component
        let header = make_node(
            "class:header.tsx:Header:1",
            "Header",
            "header.tsx",
            NodeKind::Class,
            Some("export class Header {}"),
        );
        let app_header = make_node(
            "fn:app.tsx:Header:5",
            "Header",
            "app.tsx",
            NodeKind::Function,
            Some("function Header() {}"),
        );

        // Express route
        let setup = make_node(
            "fn:routes.ts:setup:1",
            "setup",
            "routes.ts",
            NodeKind::Function,
            Some("function setup(app) { app.get('/health', healthCheck); }"),
        );
        let handler = make_node(
            "fn:health.ts:healthCheck:1",
            "healthCheck",
            "health.ts",
            NodeKind::Function,
            Some("function healthCheck(req, res) { res.json({ok:true}); }"),
        );

        nodes_by_file.insert("header.tsx".to_string(), vec![header]);
        nodes_by_file.insert("app.tsx".to_string(), vec![app_header]);
        nodes_by_file.insert("routes.ts".to_string(), vec![setup]);
        nodes_by_file.insert("health.ts".to_string(), vec![handler]);

        let frameworks = vec!["react".to_string(), "express".to_string()];
        let edges = resolve_framework_patterns(&nodes_by_file, &frameworks);

        let react_edges: Vec<_> = edges
            .iter()
            .filter(|e| e.metadata.as_ref().unwrap().get("framework").unwrap() == "react")
            .collect();
        let express_edges: Vec<_> = edges
            .iter()
            .filter(|e| e.metadata.as_ref().unwrap().get("framework").unwrap() == "express")
            .collect();

        assert!(!react_edges.is_empty(), "Should have React edges");
        assert!(!express_edges.is_empty(), "Should have Express edges");
    }
}
