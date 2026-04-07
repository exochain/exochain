# Analytics & Insights Dashboard -- Implementation Plan

**Author:** Atlas (Systems Architect)
**Date:** 2026-03-26
**Status:** Ready for review
**Assigned to:** Lumen (implementation), Atlas (architecture oversight)

---

## 1. The Hierarchy: How Max's Work Is Structured

Max described five levels: Tasks, Missions, Projects, Visions, End Goals. Here is how those map to something buildable and immediately useful, given what already exists in the database.

### Hierarchy Definition

| Level | What It Is | Database Reality | Example |
|-------|-----------|-----------------|---------|
| **Task** | A single unit of work with a clear deliverable | `tasks` table -- already exists, 5 rows | "Build database interface" |
| **Mission** | A group of related tasks sent together or toward one objective | NEW -- `missions` table (lightweight grouping) | "Set up the full dashboard UI" (contains tasks 1, 2, 4) |
| **Project** | A product or initiative with its own identity | `projects` table -- already exists, 3 rows | "Clipper Engine" |
| **Vision** | A strategic goal or milestone within a project | NEW -- `visions` table | "Clipper Engine v1 launch" |
| **End Goal** | The ultimate outcome Max is building toward (life-level) | NEW -- `end_goals` table | "Run a profitable solo media-tech company by 19" |

### Why This Hierarchy Matters for Analytics

Without hierarchy, all Max sees is a flat list of tasks. With it, the dashboard can answer:
- "What percentage of Clipper Engine's v1 vision is done?"
- "Am I spending all my time on infrastructure and ignoring my actual products?"
- "Which end goal is getting the most work?"

The key insight: **tasks flow upward**. Every task belongs to a mission (or is standalone). Missions belong to projects. Projects serve visions. Visions serve end goals. The analytics roll up at every level.

---

## 2. Database Changes

### New Tables

```sql
-- Missions: groups of related tasks (lighter than projects, heavier than tasks)
CREATE TABLE missions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    project_id INTEGER REFERENCES projects(id),
    status TEXT NOT NULL DEFAULT 'active'
        CHECK(status IN ('active', 'completed', 'archived')),
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    completed_at TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);

-- Link tasks to missions (a task can belong to one mission)
CREATE TABLE mission_tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mission_id INTEGER NOT NULL REFERENCES missions(id) ON DELETE CASCADE,
    task_id INTEGER NOT NULL REFERENCES tasks(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    UNIQUE(mission_id, task_id)
);

-- Visions: strategic milestones within a project
CREATE TABLE visions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    project_id INTEGER REFERENCES projects(id),
    target_date TEXT,           -- optional deadline
    status TEXT NOT NULL DEFAULT 'active'
        CHECK(status IN ('active', 'reached', 'revised', 'archived')),
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    reached_at TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);

-- End Goals: life-level objectives that projects serve
CREATE TABLE end_goals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT,
    target_date TEXT,
    status TEXT NOT NULL DEFAULT 'active'
        CHECK(status IN ('active', 'reached', 'revised', 'archived')),
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    reached_at TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
);

-- Link projects to end goals (many-to-many: a project can serve multiple goals)
CREATE TABLE project_goals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    end_goal_id INTEGER NOT NULL REFERENCES end_goals(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    UNIQUE(project_id, end_goal_id)
);

-- Link projects to visions is already implicit (visions.project_id)
-- But we also need: which visions serve which end goals
CREATE TABLE vision_goals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    vision_id INTEGER NOT NULL REFERENCES visions(id) ON DELETE CASCADE,
    end_goal_id INTEGER NOT NULL REFERENCES end_goals(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    UNIQUE(vision_id, end_goal_id)
);
```

### Schema Modification to Existing Tables

```sql
-- Add mission_id to tasks for direct lookup (optional -- mission_tasks handles this,
-- but a direct FK is faster for queries and simpler for the common case of 1 task = 1 mission)
-- DECISION: Use mission_tasks join table only. No FK on tasks. Keeps tasks clean.

-- Add project_id to missions (already in schema above)
-- This means: Task -> Mission -> Project -> Vision -> End Goal
-- But also:   Task -> Project (via project_tasks, for tasks not in any mission)
```

No changes to existing tables. All new tables. Zero migration risk.

---

## 3. Charts & Visualizations -- What to Build

Every chart below is specified with: type, data source SQL, what question it answers, and interaction behavior.

### 3A. TOP-LEVEL COMMAND BASE (the landing view)

#### Chart 1: Hierarchy Map (Tree/Sunburst)
- **Type:** Interactive sunburst diagram (SVG, concentric rings)
- **Center ring:** End Goals
- **Second ring:** Projects (sized by task count)
- **Third ring:** Visions (colored by status)
- **Outer ring:** Missions (colored by completion %)
- **Data source:** All hierarchy tables joined together
- **What it reveals:** Where Max's work is concentrated at a glance. Immediately shows if one project is getting all the attention while another is starved.
- **Interaction:** Hover shows name + completion %. Click any segment to drill into that level's detail view. The sunburst re-centers on the clicked segment.
- **Why sunburst:** Max has aphantasia. A sunburst gives him a single visual that encodes proportion, hierarchy, and status simultaneously. No mental rotation needed -- it is all visible at once.

#### Chart 2: Momentum Line (Time Series)
- **Type:** Multi-line SVG chart with area fill
- **X-axis:** Time (days, auto-scaling from first activity to today)
- **Y-axis:** Cumulative completed tasks
- **Lines:** One per project (color-coded), plus an "all" line
- **Data source:** `tasks.completed_at` joined with `project_tasks`
- **What it reveals:** Is Max gaining speed or losing it? Which projects are actually moving? Are there dead periods?
- **Interaction:** Hover any point to see a tooltip with date, task count, and the specific tasks completed that day. Click a point to see the task list in a slide-out panel.
- **Design detail:** The area under each line is filled with a 10% opacity version of the line color. This creates a stacked visual that shows total volume AND per-project breakdown.

#### Chart 3: Status Pipeline (Horizontal Stacked Bar)
- **Type:** Single horizontal stacked bar, full-width
- **Segments:** new | routing | in_progress | review | completed | delivered
- **Each segment:** Width proportional to count, colored by status
- **Data source:** `SELECT status, COUNT(*) FROM tasks GROUP BY status`
- **What it reveals:** Where work is stuck. If "review" is huge and "delivered" is small, there is a bottleneck. If "new" is huge, tasks are piling up.
- **Interaction:** Hover a segment to see count and percentage. Click to filter the task list below to that status.

#### Chart 4: Priority Heatmap (Weekly Grid)
- **Type:** Grid of cells, rows = priority levels, columns = days of the week
- **Cell color:** Intensity based on number of tasks created at that priority on that day
- **Data source:** `tasks.created_at` and `tasks.priority`, grouped by day-of-week and priority
- **What it reveals:** When does Max create urgent tasks? Is there a pattern? Does he dump everything on Monday?
- **Note:** This becomes more useful over time. With 5 tasks it is sparse. With 50 it tells a story.

### 3B. PROJECT DEEP-DIVE (when you click into a project)

#### Chart 5: Project Progress Ring
- **Type:** Donut chart (SVG arc paths)
- **Segments:** Tasks by status within this project
- **Center text:** "X% complete" (completed+delivered / total)
- **Data source:** `project_tasks` joined with `tasks`, grouped by status
- **What it reveals:** How close is this project to done?
- **Interaction:** Hover segments for counts. The ring animates on load (fills from 0 to current).

#### Chart 6: Project Activity Timeline
- **Type:** Vertical timeline with dots and cards
- **Data source:** `activity_log` filtered by task_ids in this project
- **Each entry:** Dot (color-coded by action type) + timestamp + actor + description
- **What it reveals:** The full narrative of what happened in this project, when, and who did it.
- **Interaction:** Click any entry to see full details. Filter by actor or action type.

#### Chart 7: Team Contribution Bar Chart
- **Type:** Horizontal bar chart
- **Each bar:** A team member, bar length = number of tasks they handled in this project
- **Bar segments:** Colored by task status (delivered, in_progress, etc.)
- **Data source:** `task_assignments` joined with `project_tasks`
- **What it reveals:** Who is carrying this project? Is one person overloaded?

### 3C. TEAM & WORKLOAD VIEW

#### Chart 8: Team Workload Radar
- **Type:** Radar/spider chart (SVG polygon)
- **Axes:** One per team member
- **Values:** Active task count per member
- **Overlay:** A second polygon showing completed task count (ghosted)
- **Data source:** `tasks` grouped by `assigned_to` and status
- **What it reveals:** Is the workload balanced? Who is idle, who is slammed?
- **Interaction:** Hover an axis to see the member's full task breakdown.

#### Chart 9: Revision Rate (Quality Indicator)
- **Type:** Bar chart with warning threshold line
- **X-axis:** Team members (or tasks)
- **Y-axis:** `revision_count` from tasks
- **Threshold line:** At revision_count = 2 (anything above = quality concern)
- **Data source:** `tasks.revision_count` grouped by `assigned_to`
- **What it reveals:** Which work keeps getting sent back? Where is the quality problem?

### 3D. TIME & ATTENTION VIEW

#### Chart 10: Calendar Allocation Pie
- **Type:** Pie chart (SVG)
- **Slices:** Calendar event types (personal, work, media, project)
- **Size:** Total hours per type
- **Data source:** `calendar_events`, calculated as `end_time - start_time` grouped by `calendar_type`
- **What it reveals:** Where is Max's scheduled time actually going?
- **Interaction:** Click a slice to see the events in that category.

#### Chart 11: Daily Schedule Density
- **Type:** Heatmap grid (rows = hours 6am-10pm, columns = days)
- **Cell intensity:** Number of scheduled events in that hour-block
- **Data source:** `calendar_events.start_time` bucketed by hour and day
- **What it reveals:** When is Max overbooked? When are there gaps? This is especially valuable for someone with aphantasia -- it makes the invisible shape of the week visible.

#### Chart 12: Focus Score Sparklines
- **Type:** Small inline sparkline charts (one per project)
- **Data:** Tasks completed per day over the last 14 days for each project
- **Displayed:** Next to project name in a compact row
- **What it reveals:** At a glance, which projects are getting daily attention and which have flatlined.

---

## 4. Page Layout

The analytics page uses a **tab-based layout** with four views, each answering a different question. This keeps the page from being overwhelming while giving Max depth when he wants it.

### Navigation: Sidebar Entry
- Add "Analytics" to the sidebar between "Dashboard" and "Calendar"
- Icon: A chart/trending-up SVG icon
- Route: `#analytics` (with sub-routes `#analytics/command`, `#analytics/projects`, `#analytics/team`, `#analytics/time`)

### Tab Bar (top of analytics page)
```
[ Command Base ]  [ Projects ]  [ Team ]  [ Time & Focus ]
```

### Tab 1: Command Base (default view)
```
+------------------------------------------------------------------+
|  ANALYTICS                                     [date range picker] |
|  [ Command Base ]  [ Projects ]  [ Team ]  [ Time & Focus ]    |
+------------------------------------------------------------------+
|                                                                    |
|  +---------------------------+  +-------------------------------+  |
|  |                           |  |                               |  |
|  |    HIERARCHY SUNBURST     |  |      MOMENTUM LINE CHART      |  |
|  |      (Chart 1)            |  |         (Chart 2)             |  |
|  |    End Goals > Projects   |  |   Cumulative tasks over time  |  |
|  |    > Visions > Missions   |  |   One line per project        |  |
|  |                           |  |                               |  |
|  +---------------------------+  +-------------------------------+  |
|                                                                    |
|  +--------------------------------------------------------------+  |
|  |  STATUS PIPELINE  (Chart 3)                                  |  |
|  |  [new][routing][in_progress][review][completed][delivered]    |  |
|  +--------------------------------------------------------------+  |
|                                                                    |
|  +--------------------------------------------------------------+  |
|  |  PRIORITY HEATMAP  (Chart 4)                                 |  |
|  |  Mon  Tue  Wed  Thu  Fri  Sat  Sun                           |  |
|  |  [cells colored by task creation intensity per priority]      |  |
|  +--------------------------------------------------------------+  |
|                                                                    |
|  +--------------------------------------------------------------+  |
|  |  QUICK STATS ROW                                             |  |
|  |  [Total Tasks: 5] [Delivered: 3] [Avg Time: 12m] [Rev: 0]   |  |
|  +--------------------------------------------------------------+  |
+------------------------------------------------------------------+
```

### Tab 2: Projects
```
+------------------------------------------------------------------+
|  +--------------------------------------------------------------+  |
|  |  PROJECT SELECTOR (horizontal pills/chips for each project)  |  |
|  |  [ All ] [Founding & Infra] [Clipper Engine] [Anim Studio]   |  |
|  +--------------------------------------------------------------+  |
|                                                                    |
|  +---------------------------+  +-------------------------------+  |
|  |                           |  |                               |  |
|  |   PROJECT PROGRESS RING   |  |   TEAM CONTRIBUTION BARS     |  |
|  |      (Chart 5)            |  |        (Chart 7)              |  |
|  |   Donut with % center     |  |   Who did what in this proj   |  |
|  |                           |  |                               |  |
|  +---------------------------+  +-------------------------------+  |
|                                                                    |
|  +--------------------------------------------------------------+  |
|  |  PROJECT ACTIVITY TIMELINE  (Chart 6)                        |  |
|  |  Vertical timeline of all actions in this project            |  |
|  |  Filter: [All] [Deliveries] [Assignments] [Reviews]          |  |
|  +--------------------------------------------------------------+  |
|                                                                    |
|  +--------------------------------------------------------------+  |
|  |  FOCUS SPARKLINES  (Chart 12)                                |  |
|  |  Each project with a 14-day activity sparkline               |  |
|  +--------------------------------------------------------------+  |
+------------------------------------------------------------------+
```

### Tab 3: Team
```
+------------------------------------------------------------------+
|  +---------------------------+  +-------------------------------+  |
|  |                           |  |                               |  |
|  |   TEAM WORKLOAD RADAR     |  |    REVISION RATE BARS         |  |
|  |      (Chart 8)            |  |        (Chart 9)              |  |
|  |   Spider chart of load    |  |   Quality indicator per member|  |
|  |                           |  |                               |  |
|  +---------------------------+  +-------------------------------+  |
|                                                                    |
|  +--------------------------------------------------------------+  |
|  |  MEMBER CARDS (one per team member)                          |  |
|  |  +--------+  +--------+  +--------+  +--------+             |  |
|  |  | Gray   |  | Lumen  |  | Pax    |  | Zenith |  ...        |  |
|  |  | 0 open |  | 0 open |  | 0 open |  | 0 open |             |  |
|  |  | 3 done |  | 3 done |  | 1 done |  | 1 done |             |  |
|  |  | [spark]|  | [spark]|  | [spark]|  | [spark]|             |  |
|  |  +--------+  +--------+  +--------+  +--------+             |  |
|  +--------------------------------------------------------------+  |
+------------------------------------------------------------------+
```

### Tab 4: Time & Focus
```
+------------------------------------------------------------------+
|  +---------------------------+  +-------------------------------+  |
|  |                           |  |                               |  |
|  |  CALENDAR ALLOCATION PIE  |  |  DAILY SCHEDULE DENSITY       |  |
|  |      (Chart 10)           |  |       (Chart 11)              |  |
|  |  Time by category         |  |  Heatmap of busy hours        |  |
|  |                           |  |                               |  |
|  +---------------------------+  +-------------------------------+  |
|                                                                    |
|  +--------------------------------------------------------------+  |
|  |  ATTENTION TRACKER                                           |  |
|  |  Horizontal bars showing hours scheduled per project         |  |
|  |  vs tasks completed per project                              |  |
|  |  (Are you spending time where you are getting results?)      |  |
|  +--------------------------------------------------------------+  |
+------------------------------------------------------------------+
```

---

## 5. Server Endpoints

All new endpoints live under `/api/analytics/`. Each returns pre-computed data ready for rendering.

### Core Analytics Endpoints

```
GET /api/analytics/overview
```
Returns: task counts by status, total by priority, average completion time (completed_at - created_at), total revision count, task count by project. This powers the quick stats row and status pipeline.

```
GET /api/analytics/momentum?range=30d
```
Returns: Array of `{ date, project_id, project_name, completed_count, cumulative }` for the momentum line chart. The `range` param accepts `7d`, `30d`, `90d`, `all`.

```
GET /api/analytics/hierarchy
```
Returns: Nested structure of `end_goals > projects > visions > missions > tasks` with completion percentages at every level. This powers the sunburst.

```
GET /api/analytics/project/:id
```
Returns: Project-specific analytics -- task breakdown by status, team contribution counts, activity timeline entries, progress percentage.

```
GET /api/analytics/team
```
Returns: Per-member stats -- open tasks, completed tasks, revision counts, average completion time, assigned projects.

```
GET /api/analytics/heatmap?type=priority
```
Returns: Grid data for priority heatmap -- `{ day_of_week, priority, count }` rows.

```
GET /api/analytics/calendar-allocation?range=30d
```
Returns: Hours per calendar_type, plus the raw hourly density grid for the schedule heatmap.

```
GET /api/analytics/sparklines?days=14
```
Returns: Per-project array of `{ date, completed_count }` for the last N days. Compact format for sparkline rendering.

### Hierarchy Management Endpoints

```
POST   /api/end-goals          -- Create an end goal
GET    /api/end-goals          -- List all end goals
PUT    /api/end-goals/:id      -- Update an end goal
DELETE /api/end-goals/:id      -- Delete an end goal

POST   /api/visions            -- Create a vision
GET    /api/visions            -- List all visions (optionally ?project_id=X)
PUT    /api/visions/:id        -- Update a vision
DELETE /api/visions/:id        -- Delete a vision

POST   /api/missions           -- Create a mission
GET    /api/missions           -- List all missions (optionally ?project_id=X)
PUT    /api/missions/:id       -- Update a mission
DELETE /api/missions/:id       -- Delete a mission
POST   /api/missions/:id/tasks -- Link tasks to a mission
DELETE /api/missions/:id/tasks/:taskId -- Unlink a task

POST   /api/project-goals      -- Link a project to an end goal
DELETE /api/project-goals/:id  -- Unlink
```

---

## 6. Interactive Features

### Hover Behaviors
- **All charts:** Tooltip appears on hover showing the exact value, label, and relevant detail. Tooltip follows cursor, positioned to never overflow the viewport.
- **Sunburst segments:** Highlight the hovered segment + all its ancestors (shows the full hierarchy path). Display: "End Goal > Project > Vision > Mission" breadcrumb in the tooltip.
- **Line chart points:** Vertical crosshair line snaps to the nearest data point. Tooltip shows all project values at that date.
- **Heatmap cells:** Show exact count and list the task titles created that day at that priority.
- **Timeline entries:** Expand on hover to show full notes text.

### Click-Through Navigation
- **Sunburst segment click:** Re-center the sunburst on that segment (zoom in). Show that level's detail panel below the chart. Double-click or click center to zoom back out.
- **Line chart point click:** Open a slide-out panel listing the tasks completed on that date. Each task is clickable to go to `#tasks` page with that task expanded.
- **Status pipeline segment click:** Filter all visible data on the page to that status.
- **Team member radar axis click:** Navigate to that member's detail view with their personal stats.
- **Any task reference click:** Navigate to `#tasks` page with that task's detail panel open.
- **Any project reference click:** Switch to the Projects tab with that project selected.

### Filters & Controls
- **Date range picker** (top right of analytics page): Preset buttons for "7 days", "30 days", "90 days", "All time". Affects all charts on the current tab simultaneously.
- **Project filter pills** (Projects tab): Click a project to scope all charts to it. "All" shows aggregate.
- **Activity type filter** (Project timeline): Dropdown or pill toggles for action types (deliveries, assignments, reviews, etc.)

### Animations
- **On page load:** Charts animate in sequentially (sunburst fills ring by ring, line chart draws left to right, bars grow from zero). Duration: 600ms each, staggered by 100ms.
- **On data change:** Smooth transitions (CSS transitions on SVG attributes) when filters change. No jarring redraws.
- **Progress rings:** Animate from 0% to current value on first render and when project changes.

### Responsive Behavior
- Two-column grid collapses to single column below 900px width.
- Charts resize using a ResizeObserver on the container. SVG viewBox scales proportionally.
- Tooltips reposition to stay in viewport on small screens.

---

## 7. Implementation Phases

### Phase 1: Foundation (build first -- immediate value)
1. Create new database tables (missions, visions, end_goals, join tables)
2. Build all `/api/analytics/*` endpoints
3. Build the SVG chart rendering library (reusable functions for: line chart, bar chart, donut, sunburst, heatmap, sparkline, radar)
4. Build the Analytics page shell with tab navigation
5. Implement **Command Base** tab (Charts 1-4 + quick stats)

**Why first:** This gives Max a working analytics page with real data immediately. The sunburst will be sparse (no visions or end goals yet) but the momentum chart, status pipeline, priority heatmap, and quick stats all work with existing data.

### Phase 2: Project Depth
6. Implement **Projects** tab (Charts 5-7 + sparklines)
7. Add project selector pill UI
8. Build the activity timeline component

**Why second:** Max has 3 projects with real tasks. This tab immediately shows useful breakdowns.

### Phase 3: Team Intelligence
9. Implement **Team** tab (Charts 8-9 + member cards)
10. Build radar chart and revision rate visualizations

**Why third:** With 7 team members and growing task history, this reveals workload distribution.

### Phase 4: Time Awareness
11. Implement **Time & Focus** tab (Charts 10-11)
12. Build calendar allocation and schedule density visualizations
13. Add the attention tracker (scheduled time vs completed work correlation)

**Why last:** Requires calendar data to be meaningful. Max has 25 calendar events already, so there is enough to start, but this tab gets more valuable as the calendar fills up.

### Phase 5: Hierarchy Management
14. Build UI for creating/editing End Goals, Visions, and Missions
15. Add the "link tasks to mission" flow
16. Add the "link project to end goal" flow
17. Populate sunburst with real hierarchy data

**Why last-last:** The analytics page works without this. But once Max defines his end goals and visions, the sunburst transforms from "interesting" to "genuinely strategic." This is the payoff of the whole hierarchy system.

---

## 8. SVG Chart Library Design

Since we are using vanilla JS with no chart libraries, Lumen will build a small internal chart library. Here is the API surface to target.

### Module: `chartLib` (object on window or internal to the IIFE)

```
chartLib.line(container, { data, xKey, yKey, series, colors, hover, click, animate })
chartLib.bar(container, { data, horizontal, stacked, colors, hover, click, animate })
chartLib.donut(container, { data, valueKey, labelKey, colors, centerText, hover, click, animate })
chartLib.sunburst(container, { data, levels, colors, hover, click, animate })
chartLib.heatmap(container, { data, xLabels, yLabels, colorScale, hover })
chartLib.sparkline(container, { data, color, width, height })
chartLib.radar(container, { data, axes, series, colors, hover })
chartLib.tooltip(event, content)  -- shared tooltip renderer
```

Each function:
- Takes a container DOM element and a config object
- Returns a `{ update(newData), destroy() }` handle for re-rendering
- All rendering uses SVG elements created via `document.createElementNS`
- Animations use `requestAnimationFrame` with easing functions
- Responsive: uses `ResizeObserver` to redraw on container resize
- Tooltip: single shared `<div>` positioned absolutely, shown/hidden by chart interactions

### Color System
Use the existing CSS custom properties from the app's design system. Define a palette of 8 distinct project/member colors as additional CSS vars:

```
--chart-1: #4F8CFF   (blue)
--chart-2: #34D399   (green)
--chart-3: #F59E0B   (amber)
--chart-4: #EF4444   (red)
--chart-5: #8B5CF6   (purple)
--chart-6: #EC4899   (pink)
--chart-7: #06B6D4   (cyan)
--chart-8: #F97316   (orange)
```

Status colors reuse existing pill colors from the design system.

---

## 9. What Max Gets Value From TODAY

With the current data (5 tasks, 3 projects, 30 activity log entries, 25 calendar events, 7 team members):

| Chart | Immediate Value | Grows With Use |
|-------|----------------|----------------|
| Status Pipeline | Shows 3 delivered, 1 routing, 1 new -- instantly visible | Reveals bottlenecks as volume grows |
| Momentum Line | Shows the founding-day burst of 3 completions | Tracks velocity over weeks and months |
| Team Contribution | Lumen did all 3 delivered tasks -- visible immediately | Shows who carries which projects |
| Calendar Allocation | 20 work events, 5 project events -- time split is visible | Patterns emerge over weeks |
| Quick Stats | Avg completion time (~15 min for founding tasks) | Benchmarks future performance |
| Revision Rate | All zeros right now (good) | Catches quality issues early |
| Focus Sparklines | Sparse but shows which days had activity | Tells the story of attention over time |
| Sunburst | Shallow (just projects and tasks) until goals/visions added | Becomes the strategic navigation center |

The dashboard is designed to be valuable with 5 tasks and transformative with 50.

---

## 10. Files to Create/Modify

| File | Action | What Changes |
|------|--------|-------------|
| `the_team.db` | ALTER | Add 6 new tables (missions, mission_tasks, visions, end_goals, project_goals, vision_goals) |
| `app/server.js` | MODIFY | Add ~200 lines: 8 analytics endpoints + 12 hierarchy CRUD endpoints |
| `app/public/app.js` | MODIFY | Add ~800 lines: renderAnalytics function, tab switching, chart library, all 12 chart renderers |
| `app/public/styles.css` | MODIFY | Add ~200 lines: analytics page layout, chart containers, tab styles, tooltip styles, responsive breakpoints |
| `app/public/index.html` | MODIFY | Add 1 sidebar nav item for Analytics |

No new files. Everything integrates into the existing single-file architecture.

---

## 11. Open Questions for Max

These do not block implementation but would improve the result:

1. **End Goals:** Does Max want to define his end goals now so the sunburst has real data from day one? Or build the UI first and fill it in later?
2. **Calendar focus:** The calendar has 25 events from March 16-20. Is Max syncing his Google Calendar regularly, or was that a one-time import? This affects how useful the time/focus tab will be.
3. **Mission grouping:** Should Gray auto-create missions from related tasks sent together, or should Max manually group them?
4. **Target dates:** Does Max want deadline/target-date tracking on visions and end goals? This would enable "days until deadline" countdowns and timeline views.

---

## Validation Gates

Before marking each phase complete:

- [ ] Phase 1: All 4 Command Base charts render with real data from the database. Hover tooltips work. Date range picker filters all charts. Page loads in under 500ms.
- [ ] Phase 2: Project selector switches all charts. Activity timeline shows correct entries. Sparklines render for each project.
- [ ] Phase 3: Radar chart shows all 7 team members. Revision rate bars are accurate. Member cards show correct counts.
- [ ] Phase 4: Calendar allocation matches manual count of events. Schedule density grid renders correctly for the existing 25 events.
- [ ] Phase 5: End goals, visions, and missions can be created, linked, and appear in the sunburst. The full hierarchy chain works: Task > Mission > Project > Vision > End Goal.
