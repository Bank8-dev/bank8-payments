// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Bank8:Payments
// SPDX-License-Identifier: Apache-2.0

//! Bank8:Payments Admin UI handlers - RFW (Remote Flutter Widget) definitions.
//! Each handler returns an `AdminUiPage` that Sentin8:Dash fetches via
//! `GET /v1/admin/ui/{page}` and renders at runtime.

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use sentin8::rfw::page::*;
use sentin8::rfw::response::AdminUiResponse;
use sentin8::rfw::widget::*;

use crate::handlers::AppState;
#[utoipa::path(
    get,
    path = "/v1/admin/ui/{page}",
    responses(
        (status = 200, description = "OK", body = serde_json::Value),
        (status = 401, description = "Not authenticated"),
        (status = 403, description = "Missing the payments scope gate"),
    ),
    security(),
    tag = "admin-ui",
)]

/// GET /v1/admin/ui/{page} - return RFW definition for the requested admin page.
pub async fn get_admin_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(page): Path<String>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let _a = crate::auth::verify_token(&state.config, &headers).await?;
    crate::policy::require(
        &state.policy,
        &_a,
        &headers,
        sentin8::shield::EvalTarget::new("bank8:payments:instructions:read"),
    )
    .await?;

    let page_def = match page.as_str() {
        "overview" => overview_page(),
        "instructions" => instructions_page(),
        "payments" => payments_page(),
        "rules" => rules_page(),
        "cards" => cards_page(),
        "files" => files_page(),
        "integrations" => integrations_page(),
        "parameters" => parameters_page(),
        "cores" => cores_page(),
        "mandates" => mandates_page(),
        "directories" => directories_page(),
        "calendars" => calendars_page(),
        "decisions" => decisions_page(),
        "simulator" => simulator_page(),
        "settings" => settings_page(),
        // ── Policy Studio (design §3.7, story 28.14) - shared page
        // constructors; the guard guarantees `Some` (§3.7 dispatch).
        p if sentin8::rfw::policy_page("bank8:payments", p).is_some() => {
            sentin8::rfw::policy_page("bank8:payments", p)
                .expect("policy_page checked in guard")
                .build()
        }
        _ => {
            return Err((
                axum::http::StatusCode::NOT_FOUND,
                format!("Unknown admin UI page: {page}"),
            ))
        }
    };

    Ok(Json(
        serde_json::to_value(AdminUiResponse::page(page_def)).unwrap(),
    ))
}

fn overview_page() -> AdminUiPage {
    AdminPage::new("Payments Overview")
        .widget(RemoteWidget::Card(WidgetCard {
            title: Some("Instructions Summary".into()),
            subtitle: None,
            children: vec![RemoteWidget::Text(WidgetText {
                text:
                    "Instructions, rules, cards, files, integrations, manual decisions, simulator."
                        .into(),
                text_type: WidgetTextType::Body,
                align: TextAlign::Left,
                max_lines: None,
            })],
            actions: vec![],
        }))
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "id".into(),
                    label: "Instruction ID".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "state".into(),
                    label: "State".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "created_at".into(),
                    label: "Created".into(),
                    sortable: true,
                    width: None,
                    format: Some("datetime".into()),
                },
            ],
            data_endpoint: "/instructions".into(),
            sortable: true,
            filterable: true,
            page_size: 20,
            empty_message: Some("No instructions found.".into()),
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

fn instructions_page() -> AdminUiPage {
    AdminPage::new("Instructions")
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "id".into(),
                    label: "Instruction ID".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "state".into(),
                    label: "State".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "correlation_id".into(),
                    label: "Correlation ID".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "created_at".into(),
                    label: "Created".into(),
                    sortable: true,
                    width: None,
                    format: Some("datetime".into()),
                },
            ],
            data_endpoint: "/instructions".into(),
            sortable: true,
            filterable: true,
            page_size: 20,
            empty_message: Some("No instructions found.".into()),
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

fn payments_page() -> AdminUiPage {
    AdminPage::new("Payments")
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "id".into(),
                    label: "Payment ID".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "status".into(),
                    label: "Status".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "amount".into(),
                    label: "Amount".into(),
                    sortable: true,
                    width: None,
                    format: Some("currency".into()),
                },
            ],
            data_endpoint: "/payments".into(),
            sortable: true,
            filterable: true,
            page_size: 20,
            empty_message: Some("No payments found.".into()),
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

fn rules_page() -> AdminUiPage {
    AdminPage::new("Rules")
        .action(AdminUiAction {
            label: "Create Rule".into(),
            action_type: AdminUiActionType::Link,
            route: Some("rules/new".into()),
            endpoint: None,
            icon: Some("add".into()),
        })
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "id".into(),
                    label: "Rule ID".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "name".into(),
                    label: "Name".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "status".into(),
                    label: "Status".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
            ],
            data_endpoint: "/rules".into(),
            sortable: true,
            filterable: false,
            page_size: 20,
            empty_message: Some("No rules found.".into()),
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

fn cards_page() -> AdminUiPage {
    AdminPage::new("Cards")
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "id".into(),
                    label: "Card ID".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "holder_name".into(),
                    label: "Cardholder".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "status".into(),
                    label: "Status".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
            ],
            data_endpoint: "/cards".into(),
            sortable: true,
            filterable: true,
            page_size: 20,
            empty_message: Some("No cards found.".into()),
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

fn files_page() -> AdminUiPage {
    AdminPage::new("Files")
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "id".into(),
                    label: "File ID".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "name".into(),
                    label: "Name".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "status".into(),
                    label: "Status".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
            ],
            data_endpoint: "/files".into(),
            sortable: true,
            filterable: false,
            page_size: 20,
            empty_message: Some("No files found.".into()),
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

fn integrations_page() -> AdminUiPage {
    AdminPage::new("Integrations")
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "id".into(),
                    label: "Integration ID".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "name".into(),
                    label: "Name".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "status".into(),
                    label: "Status".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
            ],
            data_endpoint: "/integrations".into(),
            sortable: true,
            filterable: false,
            page_size: 20,
            empty_message: Some("No integrations found.".into()),
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

fn parameters_page() -> AdminUiPage {
    AdminPage::new("Parameters")
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "id".into(),
                    label: "Parameter ID".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "name".into(),
                    label: "Name".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "type".into(),
                    label: "Type".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
            ],
            data_endpoint: "/parameters".into(),
            sortable: true,
            filterable: false,
            page_size: 20,
            empty_message: Some("No parameters found.".into()),
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

fn cores_page() -> AdminUiPage {
    AdminPage::new("Cores")
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "id".into(),
                    label: "Core ID".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "name".into(),
                    label: "Name".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
            ],
            data_endpoint: "/cores".into(),
            sortable: true,
            filterable: false,
            page_size: 20,
            empty_message: Some("No cores found.".into()),
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

fn mandates_page() -> AdminUiPage {
    AdminPage::new("Mandates (BETA)")
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "id".into(),
                    label: "Mandate ID".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "status".into(),
                    label: "Status".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
            ],
            data_endpoint: "/mandates".into(),
            sortable: true,
            filterable: false,
            page_size: 20,
            empty_message: Some("No mandates found.".into()),
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

fn directories_page() -> AdminUiPage {
    AdminPage::new("Membership Directories")
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "id".into(),
                    label: "Directory ID".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "name".into(),
                    label: "Name".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
            ],
            data_endpoint: "/directories".into(),
            sortable: true,
            filterable: false,
            page_size: 20,
            empty_message: Some("No directories found.".into()),
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

fn calendars_page() -> AdminUiPage {
    AdminPage::new("Calendars")
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "id".into(),
                    label: "Calendar ID".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "name".into(),
                    label: "Name".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
            ],
            data_endpoint: "/calendars".into(),
            sortable: true,
            filterable: false,
            page_size: 20,
            empty_message: Some("No calendars found.".into()),
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

fn decisions_page() -> AdminUiPage {
    AdminPage::new("Manual Decisions")
        .widget(RemoteWidget::DataTable(WidgetDataTable {
            columns: vec![
                WidgetDataTableColumn {
                    key: "id".into(),
                    label: "Decision ID".into(),
                    sortable: false,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "status".into(),
                    label: "Status".into(),
                    sortable: true,
                    width: None,
                    format: None,
                },
                WidgetDataTableColumn {
                    key: "created_at".into(),
                    label: "Created".into(),
                    sortable: true,
                    width: None,
                    format: Some("datetime".into()),
                },
            ],
            data_endpoint: "/decisions".into(),
            sortable: true,
            filterable: false,
            page_size: 20,
            empty_message: Some("No pending decisions.".into()),
            row_link: None,
            row_actions: vec![],
        }))
        .build()
}

fn simulator_page() -> AdminUiPage {
    AdminPage::new("Simulator")
        .widget(RemoteWidget::Native(WidgetNative {
            widget_name: "payment_simulator".into(),
            props: serde_json::json!({}),
            data_endpoint: Some("/simulator/run".into()),
        }))
        .build()
}

fn settings_page() -> AdminUiPage {
    AdminPage::new("Payments Settings")
        .widget(RemoteWidget::Text(WidgetText {
            text: "Bank8:Payments configuration settings.".into(),
            text_type: WidgetTextType::Body,
            align: TextAlign::Left,
            max_lines: None,
        }))
        .build()
}
