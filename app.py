import csv
from functools import wraps
import io
from flask import (
    Flask,
    Response,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import generate_password_hash
from config import FIREBASE_CONFIG, SECRET_KEY
from firebase_service import (
    add_student_to_class,
    authenticate_user,
    bulk_upsert_students,
    clear_class_students,
    compute_cbt_status,
    create_cbt_test,
    create_class_assessment,
    create_class_page,
    create_lecture_session,
    create_user,
    delete_cbt_test,
    delete_class_assessment,
    delete_class_page,
    delete_lecture_session,
    delete_student,
    delete_user,
    enrich_students_with_assessments,
    ensure_default_admin,
    find_duplicate_student_in_class,
    generate_sample_cbt_xlsx_bytes,
    generate_sample_xlsx_bytes,
    get_all_lecturers,
    get_assessment_by_id,
    get_assessments_by_class,
    get_cbt_test_by_id,
    get_cbt_tests_by_class,
    get_class_by_code,
    get_class_by_id,
    get_classes_by_lecturer,
    get_firebase_usage_stats,
    get_session_by_id,
    get_sessions_by_class,
    get_student_by_id,
    get_students_by_class,
    get_user_by_id,
    list_all_classes,
    parse_cbt_questions_spreadsheet,
    parse_scores_spreadsheet,
    parse_students_spreadsheet,
    reset_cbt_student_attempt,
    save_assessment_scores,
    student_self_register_in_class,
    student_self_update_matric,
    submit_cbt_student_attempt,
    update_cbt_test_fields,
    update_class_fields,
    update_student_fields,
    update_user_fields,
    verify_student_in_class,
)

app = Flask(__name__)
app.secret_key = SECRET_KEY


@app.context_processor
def inject_firebase_config():
    return {
        "firebase_config": FIREBASE_CONFIG,
        "firebase_usage": get_firebase_usage_stats(),
    }


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in to access this page.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            flash("Access restricted to Administrators only.", "danger")
            return redirect(url_for("lecturer_dashboard"))
        return f(*args, **kwargs)

    return decorated_function


def lecturer_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please sign in to continue.", "warning")
            return redirect(url_for("login"))
        if session.get("role") != "lecturer":
            flash("Access restricted to Lecturers.", "danger")
            return redirect(url_for("admin_dashboard"))
        return f(*args, **kwargs)

    return decorated_function


@app.route("/")
def index():
    if "user_id" in session:
        if session.get("role") == "admin":
            return redirect(url_for("admin_dashboard"))
        return redirect(url_for("lecturer_dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("index"))

    # Ensure at least one default admin exists in Firebase Firestore
    ensure_default_admin()

    selected_role = request.args.get("role", "lecturer")
    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")
        selected_role = request.form.get("role", "lecturer").strip().lower()

        result = authenticate_user(identifier, password, expected_role=selected_role)
        if result["ok"]:
            user = result["user"]
            session["user_id"] = user["id"]
            session["full_name"] = user.get("full_name", "")
            session["email"] = user.get("email", "")
            session["role"] = user.get("role", "lecturer")
            session["staff_id"] = user.get("staff_id", "")
            session["department"] = user.get("department", "")

            flash(f"Welcome back, {user.get('full_name')}!", "success")
            if user.get("role") == "admin":
                return redirect(url_for("admin_dashboard"))
            return redirect(url_for("lecturer_dashboard"))
        else:
            flash(result["error"], "danger")

    return render_template("login.html", selected_role=selected_role)


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been signed out successfully.", "info")
    return redirect(url_for("login"))


# ==========================================
# ADMIN ROUTES
# ==========================================
@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    lecturers = get_all_lecturers()
    all_classes = list_all_classes()
    active_count = sum(1 for lec in lecturers if lec.get("status", "active") == "active")
    departments = sorted(
        {lec.get("department", "").strip() for lec in lecturers if lec.get("department", "").strip()}
    )

    # Count classes per lecturer
    class_counts = {}
    for cls in all_classes:
        lid = cls.get("lecturer_id", "")
        class_counts[lid] = class_counts.get(lid, 0) + 1

    # Generate suggested next Staff ID
    next_num = len(lecturers) + 1
    suggested_staff_id = f"LEC-2026-{next_num:03d}"

    return render_template(
        "admin_dashboard.html",
        lecturers=lecturers,
        all_classes=all_classes,
        class_counts=class_counts,
        total_lecturers=len(lecturers),
        active_lecturers=active_count,
        departments_count=len(departments),
        total_classes=len(all_classes),
        suggested_staff_id=suggested_staff_id,
    )


@app.route("/admin/lecturers/add", methods=["POST"])
@admin_required
def add_lecturer():
    full_name = request.form.get("full_name", "").strip()
    email = request.form.get("email", "").strip().lower()
    staff_id = request.form.get("staff_id", "").strip().upper()
    department = request.form.get("department", "").strip()
    phone = request.form.get("phone", "").strip()
    password = request.form.get("password", "").strip()

    if not all([full_name, email, staff_id, department, password]):
        flash("Please fill in all required fields (Name, Email, Staff ID, Department, Password).", "danger")
        return redirect(url_for("admin_dashboard"))

    if len(password) < 6:
        flash("Password must be at least 6 characters long.", "danger")
        return redirect(url_for("admin_dashboard"))

    res = create_user(
        full_name=full_name,
        email=email,
        password=password,
        role="lecturer",
        staff_id=staff_id,
        department=department,
        phone=phone,
        created_by=session.get("email", "admin"),
    )

    if res["ok"]:
        flash(
            f"Lecturer '{full_name}' ({staff_id}) added successfully! They can now log in with {email} or {staff_id}.",
            "success",
        )
    else:
        flash(res["error"], "danger")

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/lecturers/<doc_id>/toggle-status", methods=["POST"])
@admin_required
def toggle_lecturer_status(doc_id):
    user = get_user_by_id(doc_id)
    if not user or user.get("role") != "lecturer":
        flash("Lecturer account not found.", "danger")
        return redirect(url_for("admin_dashboard"))

    current_status = user.get("status", "active")
    new_status = "inactive" if current_status == "active" else "active"
    res = update_user_fields(doc_id, {"status": new_status})
    if res["ok"]:
        state_word = "activated" if new_status == "active" else "deactivated"
        flash(f"Lecturer {user.get('full_name')} has been {state_word}.", "success")
    else:
        flash(res["error"], "danger")

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/lecturers/<doc_id>/reset-password", methods=["POST"])
@admin_required
def reset_lecturer_password(doc_id):
    new_password = request.form.get("new_password", "").strip()
    if len(new_password) < 6:
        flash("New password must be at least 6 characters.", "danger")
        return redirect(url_for("admin_dashboard"))

    user = get_user_by_id(doc_id)
    if not user or user.get("role") != "lecturer":
        flash("Lecturer account not found.", "danger")
        return redirect(url_for("admin_dashboard"))

    res = update_user_fields(doc_id, {"password_hash": generate_password_hash(new_password)})
    if res["ok"]:
        flash(f"Password updated for {user.get('full_name')}.", "success")
    else:
        flash(res["error"], "danger")

    return redirect(url_for("admin_dashboard"))


@app.route("/admin/lecturers/<doc_id>/delete", methods=["POST"])
@admin_required
def remove_lecturer(doc_id):
    user = get_user_by_id(doc_id)
    if not user or user.get("role") != "lecturer":
        flash("Lecturer account not found.", "danger")
        return redirect(url_for("admin_dashboard"))

    res = delete_user(doc_id)
    if res["ok"]:
        flash(f"Lecturer '{user.get('full_name')}' removed from the system.", "info")
    else:
        flash(res["error"], "danger")

    return redirect(url_for("admin_dashboard"))


# ==========================================
# LECTURER & CLASS PAGE ROUTES
# ==========================================
@app.route("/lecturer/dashboard")
@lecturer_required
def lecturer_dashboard():
    user = get_user_by_id(session.get("user_id"))
    if not user:
        session.clear()
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for("login"))

    classes = get_classes_by_lecturer(user["id"])
    active_classes = sum(1 for c in classes if c.get("status", "active") == "active")
    total_units = sum(int(c.get("credit_units") or 0) for c in classes)

    return render_template(
        "lecturer_dashboard.html",
        lecturer=user,
        classes=classes,
        total_classes=len(classes),
        active_classes=active_classes,
        total_units=total_units,
    )


@app.route("/lecturer/classes/create", methods=["POST"])
@lecturer_required
def create_lecturer_class():
    user = get_user_by_id(session.get("user_id"))
    if not user:
        session.clear()
        flash("Session expired. Please log in again.", "warning")
        return redirect(url_for("login"))

    course_code = request.form.get("course_code", "").strip().upper()
    course_title = request.form.get("course_title", "").strip()
    level = request.form.get("level", "100 Level").strip()
    semester = request.form.get("semester", "First Semester").strip()
    academic_session = request.form.get("academic_session", "2025/2026").strip()
    credit_units = request.form.get("credit_units", "3").strip()
    schedule = request.form.get("schedule", "").strip()
    venue = request.form.get("venue", "").strip()
    description = request.form.get("description", "").strip()

    if not course_code or not course_title:
        flash("Please provide both a Course Code and Course Title.", "danger")
        return redirect(url_for("lecturer_dashboard"))

    res = create_class_page(
        lecturer_id=user["id"],
        lecturer_name=user.get("full_name", ""),
        lecturer_email=user.get("email", ""),
        lecturer_staff_id=user.get("staff_id", ""),
        department=user.get("department", ""),
        course_code=course_code,
        course_title=course_title,
        level=level,
        semester=semester,
        academic_session=academic_session,
        credit_units=credit_units,
        schedule=schedule,
        venue=venue,
        description=description,
    )

    if res["ok"]:
        created_cls = res["class_page"]
        flash(
            f"Class page '{course_code}: {course_title}' created successfully!",
            "success",
        )
        return redirect(url_for("view_class_page", class_id=created_cls["id"]))
    else:
        flash(res["error"], "danger")
        return redirect(url_for("lecturer_dashboard"))


@app.route("/lecturer/classes/<class_id>")
@login_required
def view_class_page(class_id):
    cls = get_class_by_id(class_id)
    if not cls:
        flash("Class page not found.", "danger")
        return redirect(url_for("index"))

    # Lecturers can only manage their own classes; Admins can view any class page
    is_owner = session.get("user_id") == cls.get("lecturer_id")
    is_admin = session.get("role") == "admin"
    if not is_owner and not is_admin:
        flash("You do not have permission to manage this class page.", "danger")
        return redirect(url_for("lecturer_dashboard"))

    sessions = get_sessions_by_class(class_id)
    students = get_students_by_class(class_id)
    assessments = get_assessments_by_class(class_id)
    cbt_tests = get_cbt_tests_by_class(class_id)
    gradebook_totals = enrich_students_with_assessments(students, assessments)

    selected_assessment_id = request.args.get("assessment_id", "").strip()
    selected_assessment = None
    if assessments:
        for a in assessments:
            if a.get("id") == selected_assessment_id:
                selected_assessment = a
                break
        if not selected_assessment:
            selected_assessment = assessments[-1]

    selected_cbt_id = request.args.get("cbt_id", "").strip()
    selected_cbt = None
    if cbt_tests:
        for ct in cbt_tests:
            if ct.get("id") == selected_cbt_id:
                selected_cbt = ct
                break
        if not selected_cbt:
            selected_cbt = cbt_tests[0]

    matric_completed = sum(1 for s in students if s.get("has_valid_matric"))
    matric_pending = len(students) - matric_completed
    next_week = len(sessions) + 1
    active_tab = request.args.get("tab", "students")

    return render_template(
        "class_page.html",
        class_page=cls,
        sessions=sessions,
        students=students,
        assessments=assessments,
        selected_assessment=selected_assessment,
        cbt_tests=cbt_tests,
        selected_cbt=selected_cbt,
        gradebook_totals=gradebook_totals,
        matric_completed=matric_completed,
        matric_pending=matric_pending,
        next_week=next_week,
        is_owner=is_owner,
        is_admin=is_admin,
        public_view=False,
        active_tab=active_tab,
        verify_query="",
        verified_results=[],
    )


@app.route("/class/<class_code>", methods=["GET", "POST"])
def public_class_page(class_code):
    """Shareable Class Page accessible by Class Code or Document ID, with Student Self-Check."""
    cls = get_class_by_code(class_code)
    if not cls:
        cls = get_class_by_id(class_code)
    if not cls:
        flash("Class page not found.", "danger")
        return redirect(url_for("index"))

    sessions = get_sessions_by_class(cls["id"])
    students = get_students_by_class(cls["id"])
    assessments = get_assessments_by_class(cls["id"])
    cbt_tests = get_cbt_tests_by_class(cls["id"])
    gradebook_totals = enrich_students_with_assessments(students, assessments)

    selected_assessment_id = request.args.get("assessment_id", "").strip()
    selected_assessment = None
    if assessments:
        for a in assessments:
            if a.get("id") == selected_assessment_id:
                selected_assessment = a
                break
        if not selected_assessment:
            selected_assessment = assessments[-1]

    selected_cbt_id = request.args.get("cbt_id", "").strip()
    selected_cbt = None
    if cbt_tests:
        for ct in cbt_tests:
            if ct.get("id") == selected_cbt_id:
                selected_cbt = ct
                break
        if not selected_cbt:
            selected_cbt = cbt_tests[0]

    matric_completed = sum(1 for s in students if s.get("has_valid_matric"))
    matric_pending = len(students) - matric_completed

    is_owner = session.get("user_id") == cls.get("lecturer_id")
    is_admin = session.get("role") == "admin"

    verify_query = (
        request.form.get("q", "").strip()
        if request.method == "POST"
        else request.args.get("q", "").strip()
    )
    verified_results = []
    if verify_query:
        verified_results = verify_student_in_class(cls["id"], verify_query)
        enrich_students_with_assessments(verified_results, assessments)

    default_tab = "verify" if not (is_owner or is_admin) else "students"
    if verify_query:
        default_tab = "verify"
    active_tab = request.args.get("tab", default_tab)

    return render_template(
        "class_page.html",
        class_page=cls,
        sessions=sessions,
        students=students,
        assessments=assessments,
        selected_assessment=selected_assessment,
        cbt_tests=cbt_tests,
        selected_cbt=selected_cbt,
        gradebook_totals=gradebook_totals,
        matric_completed=matric_completed,
        matric_pending=matric_pending,
        next_week=len(sessions) + 1,
        is_owner=is_owner,
        is_admin=is_admin,
        public_view=True,
        active_tab=active_tab,
        verify_query=verify_query,
        verified_results=verified_results,
    )


@app.route("/class/<class_code>/update-matric", methods=["POST"])
def student_update_own_matric(class_code):
    """Allow an enrolled student on the public class page to update their Matric Number."""
    cls = get_class_by_code(class_code)
    if not cls:
        cls = get_class_by_id(class_code)
    if not cls:
        flash("Class page not found.", "danger")
        return redirect(url_for("index"))

    student_id = request.form.get("student_id", "").strip()
    verification_token = request.form.get("verification_token", "").strip()
    new_matric_number = request.form.get("new_matric_number", "").strip().upper()
    return_query = request.form.get("return_query", "").strip() or new_matric_number

    res = student_self_update_matric(
        class_id=cls["id"],
        student_id=student_id,
        verification_token=verification_token,
        new_matric_number=new_matric_number,
    )

    if res["ok"]:
        updated_st = res["student"]
        flash(
            f"Matric Number updated to '{updated_st.get('matric_number')}' for {updated_st.get('full_name')}!",
            "success",
        )
        return redirect(
            url_for("public_class_page", class_code=cls["class_code"], q=updated_st.get("matric_number"), tab="verify")
        )
    else:
        flash(res["error"], "danger")
        return redirect(
            url_for("public_class_page", class_code=cls["class_code"], q=return_query, tab="verify")
        )


@app.route("/class/<class_code>/self-register", methods=["POST"])
def student_self_register(class_code):
    """
    Allow a student on the public class page to add their details to the class list
    ONLY if the lecturer has activated `allow_self_registration`.
    """
    cls = get_class_by_code(class_code)
    if not cls:
        cls = get_class_by_id(class_code)
    if not cls:
        flash("Class page not found.", "danger")
        return redirect(url_for("index"))

    full_name = request.form.get("full_name", "").strip()
    gts_number = request.form.get("gts_number", "").strip()
    matric_number = request.form.get("matric_number", "").strip()
    phone_number = request.form.get("phone_number", "").strip()

    res = student_self_register_in_class(
        class_id=cls["id"],
        full_name=full_name,
        matric_number=matric_number,
        gts_number=gts_number,
        phone_number=phone_number,
    )

    if res.get("ok"):
        q_key = res.get("query_key") or gts_number or full_name
        flash(
            f"Your record has been added to the {cls.get('course_code')} class list! Below is your verified enrollment card.",
            "success",
        )
        return redirect(
            url_for("public_class_page", class_code=cls["class_code"], q=q_key, tab="verify")
        )
    elif res.get("already_exists"):
        st = res.get("student") or {}
        q_key = st.get("gts_number") or st.get("full_name") or gts_number or full_name
        flash(res.get("error", "You are already on the class list."), "info")
        return redirect(
            url_for("public_class_page", class_code=cls["class_code"], q=q_key, tab="verify")
        )
    else:
        flash(res.get("error", "Could not register your details."), "danger")
        return redirect(
            url_for("public_class_page", class_code=cls["class_code"], q=gts_number or full_name, tab="verify")
        )


@app.route("/lecturer/classes/<class_id>/toggle-self-registration", methods=["POST"])
@login_required
def toggle_class_self_registration(class_id):
    """Allow the lecturer (or admin) to activate or deactivate student self-registration for a class."""
    cls = get_class_by_id(class_id)
    if not cls:
        flash("Class page not found.", "danger")
        return redirect(url_for("index"))

    if session.get("user_id") != cls.get("lecturer_id") and session.get("role") != "admin":
        flash("Only the assigned lecturer can change self-registration settings.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id))

    current_state = bool(cls.get("allow_self_registration", False))
    new_state = not current_state

    res = update_class_fields(class_id, {"allow_self_registration": new_state})
    if res["ok"]:
        state_label = "ACTIVATED" if new_state else "DEACTIVATED"
        msg_type = "success" if new_state else "warning"
        flash(
            f"Student Self-Registration has been {state_label} for {cls.get('course_code')}.",
            msg_type,
        )
    else:
        flash(res["error"], "danger")

    return_tab = request.form.get("return_tab", "students")
    return redirect(url_for("view_class_page", class_id=class_id, tab=return_tab))


@app.route("/lecturer/classes/<class_id>/update", methods=["POST"])
@login_required
def update_lecturer_class(class_id):
    cls = get_class_by_id(class_id)
    if not cls:
        flash("Class page not found.", "danger")
        return redirect(url_for("index"))

    if session.get("user_id") != cls.get("lecturer_id") and session.get("role") != "admin":
        flash("Unauthorized action.", "danger")
        return redirect(url_for("index"))

    course_code = request.form.get("course_code", cls.get("course_code", "")).strip().upper()
    course_title = request.form.get("course_title", cls.get("course_title", "")).strip()
    level = request.form.get("level", cls.get("level", "")).strip()
    semester = request.form.get("semester", cls.get("semester", "")).strip()
    academic_session = request.form.get("academic_session", cls.get("academic_session", "")).strip()
    schedule = request.form.get("schedule", "").strip()
    venue = request.form.get("venue", "").strip()
    description = request.form.get("description", "").strip()
    status = request.form.get("status", cls.get("status", "active")).strip()

    try:
        credit_units = int(request.form.get("credit_units", cls.get("credit_units", 3)))
    except (ValueError, TypeError):
        credit_units = 3

    updates = {
        "course_code": course_code,
        "course_title": course_title,
        "level": level,
        "semester": semester,
        "academic_session": academic_session,
        "credit_units": credit_units,
        "schedule": schedule,
        "venue": venue,
        "description": description,
        "status": status,
    }
    if "allow_self_registration" in request.form:
        updates["allow_self_registration"] = request.form.get("allow_self_registration") == "true"

    res = update_class_fields(class_id, updates)
    if res["ok"]:
        flash("Class page updated successfully.", "success")
    else:
        flash(res["error"], "danger")

    return redirect(url_for("view_class_page", class_id=class_id))


@app.route("/lecturer/classes/<class_id>/delete", methods=["POST"])
@login_required
def delete_lecturer_class(class_id):
    cls = get_class_by_id(class_id)
    if not cls:
        flash("Class page not found.", "danger")
        return redirect(url_for("index"))

    if session.get("user_id") != cls.get("lecturer_id") and session.get("role") != "admin":
        flash("Unauthorized action.", "danger")
        return redirect(url_for("index"))

    res = delete_class_page(class_id)
    if res["ok"]:
        flash(f"Class page '{cls.get('course_code')}' deleted.", "info")
    else:
        flash(res["error"], "danger")

    if session.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))
    return redirect(url_for("lecturer_dashboard"))


@app.route("/lecturer/classes/<class_id>/sessions/add", methods=["POST"])
@login_required
def add_class_session(class_id):
    cls = get_class_by_id(class_id)
    if not cls:
        flash("Class page not found.", "danger")
        return redirect(url_for("index"))

    if session.get("user_id") != cls.get("lecturer_id") and session.get("role") != "admin":
        flash("Only the assigned lecturer can log sessions for this class.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id))

    week_number = request.form.get("week_number", "1").strip()
    topic = request.form.get("topic", "").strip()
    lecture_date = request.form.get("lecture_date", "").strip()
    start_time = request.form.get("start_time", "").strip()
    end_time = request.form.get("end_time", "").strip()
    venue = request.form.get("venue", cls.get("venue", "")).strip()
    attendance_count = request.form.get("attendance_count", "0").strip()
    summary = request.form.get("summary", "").strip()
    materials_link = request.form.get("materials_link", "").strip()

    if not topic or not lecture_date:
        flash("Please provide at least the Lecture Topic and Date.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id))

    res = create_lecture_session(
        class_id=class_id,
        lecturer_id=cls.get("lecturer_id", ""),
        week_number=week_number,
        topic=topic,
        lecture_date=lecture_date,
        start_time=start_time,
        end_time=end_time,
        venue=venue,
        attendance_count=attendance_count,
        summary=summary,
        materials_link=materials_link,
    )

    if res["ok"]:
        flash(f"Lecture record for Week {week_number} ('{topic}') added to class page!", "success")
    else:
        flash(res["error"], "danger")

    return redirect(url_for("view_class_page", class_id=class_id))


@app.route("/lecturer/classes/<class_id>/sessions/<session_id>/delete", methods=["POST"])
@login_required
def remove_class_session(class_id, session_id):
    cls = get_class_by_id(class_id)
    sess = get_session_by_id(session_id)
    if not cls or not sess:
        flash("Lecture session record not found.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id))

    if session.get("user_id") != cls.get("lecturer_id") and session.get("role") != "admin":
        flash("Unauthorized action.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id))

    res = delete_lecture_session(session_id)
    if res["ok"]:
        flash("Lecture session record removed.", "info")
    else:
        flash(res["error"], "danger")

    return redirect(url_for("view_class_page", class_id=class_id, tab="sessions"))


# ==========================================
# CLASS STUDENT RECORDS & EXCEL/CSV UPLOAD
# ==========================================
@app.route("/lecturer/classes/<class_id>/students/add", methods=["POST"])
@login_required
def add_class_student(class_id):
    cls = get_class_by_id(class_id)
    if not cls:
        flash("Class page not found.", "danger")
        return redirect(url_for("index"))

    if session.get("user_id") != cls.get("lecturer_id") and session.get("role") != "admin":
        flash("Only the assigned lecturer can add students to this class.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="students"))

    full_name = request.form.get("full_name", "").strip()
    matric_number = request.form.get("matric_number", "").strip().upper() or "NOT AVAILABLE"
    gts_number = request.form.get("gts_number", "").strip().upper()
    phone_number = request.form.get("phone_number", "").strip()

    if not full_name:
        flash("Student Full Name is required.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="students"))

    res = add_student_to_class(
        class_id=class_id,
        lecturer_id=cls.get("lecturer_id", ""),
        full_name=full_name,
        matric_number=matric_number,
        gts_number=gts_number,
        phone_number=phone_number,
    )

    if res["ok"]:
        flash(f"Student '{full_name}' ({matric_number}) added to {cls.get('course_code')}!", "success")
    else:
        flash(res["error"], "danger")

    return redirect(url_for("view_class_page", class_id=class_id, tab="students"))


@app.route("/lecturer/classes/<class_id>/students/upload", methods=["POST"])
@login_required
def upload_class_students(class_id):
    cls = get_class_by_id(class_id)
    if not cls:
        flash("Class page not found.", "danger")
        return redirect(url_for("index"))

    if session.get("user_id") != cls.get("lecturer_id") and session.get("role") != "admin":
        flash("Only the assigned lecturer can upload students for this class.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="students"))

    uploaded_file = request.files.get("students_file")
    if not uploaded_file or not uploaded_file.filename:
        flash("Please select an Excel (.xlsx) or CSV (.csv) file to upload.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="students"))

    file_bytes = uploaded_file.read()
    parsed = parse_students_spreadsheet(uploaded_file.filename, file_bytes)
    if not parsed["ok"]:
        flash(parsed["error"], "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="students"))

    res = bulk_upsert_students(
        class_id=class_id,
        lecturer_id=cls.get("lecturer_id", ""),
        students_list=parsed["students"],
    )

    if res["ok"]:
        count = res.get("count", 0)
        skipped = res.get("skipped_duplicates", 0)
        skip_note = f" ({skipped} duplicate Matric/GTS record{'s' if skipped != 1 else ''} skipped)" if skipped else ""
        flash(
            f"Successfully uploaded {count} student record{'s' if count != 1 else ''} into {cls.get('course_code')}{skip_note}!",
            "success",
        )
    else:
        flash(res["error"], "danger")

    return redirect(url_for("view_class_page", class_id=class_id, tab="students"))


@app.route("/lecturer/classes/<class_id>/students/<student_id>/update", methods=["POST"])
@login_required
def update_class_student(class_id, student_id):
    cls = get_class_by_id(class_id)
    student = get_student_by_id(student_id)
    if not cls or not student:
        flash("Student record not found.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="students"))

    if session.get("user_id") != cls.get("lecturer_id") and session.get("role") != "admin":
        flash("Unauthorized action.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="students"))

    full_name = request.form.get("full_name", student.get("full_name", "")).strip()
    matric_number = request.form.get("matric_number", student.get("matric_number", "")).strip().upper()
    gts_number = request.form.get("gts_number", student.get("gts_number", "")).strip().upper()
    phone_number = request.form.get("phone_number", student.get("phone_number", "")).strip()

    dup_check = find_duplicate_student_in_class(
        class_id=class_id,
        matric_number=matric_number,
        gts_number=gts_number,
        exclude_student_id=student_id,
    )
    if dup_check.get("duplicate"):
        flash(dup_check["error"], "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="students"))

    res = update_student_fields(
        student_id,
        {
            "full_name": full_name,
            "matric_number": matric_number,
            "gts_number": gts_number,
            "phone_number": phone_number,
        },
    )
    if res["ok"]:
        flash(f"Updated record for {full_name}.", "success")
    else:
        flash(res["error"], "danger")

    return redirect(url_for("view_class_page", class_id=class_id, tab="students"))


@app.route("/lecturer/classes/<class_id>/students/<student_id>/delete", methods=["POST"])
@login_required
def remove_class_student(class_id, student_id):
    cls = get_class_by_id(class_id)
    if not cls:
        flash("Class page not found.", "danger")
        return redirect(url_for("index"))

    if session.get("user_id") != cls.get("lecturer_id") and session.get("role") != "admin":
        flash("Unauthorized action.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="students"))

    res = delete_student(student_id)
    if res["ok"]:
        flash("Student record removed from class.", "info")
    else:
        flash(res["error"], "danger")

    return redirect(url_for("view_class_page", class_id=class_id, tab="students"))


@app.route("/lecturer/classes/<class_id>/students/clear", methods=["POST"])
@login_required
def clear_all_class_students(class_id):
    cls = get_class_by_id(class_id)
    if not cls:
        flash("Class page not found.", "danger")
        return redirect(url_for("index"))

    if session.get("user_id") != cls.get("lecturer_id") and session.get("role") != "admin":
        flash("Unauthorized action.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="students"))

    res = clear_class_students(class_id)
    if res["ok"]:
        flash(f"Cleared {res.get('deleted', 0)} student records from {cls.get('course_code')}.", "info")
    else:
        flash(res["error"], "danger")

    return redirect(url_for("view_class_page", class_id=class_id, tab="students"))


@app.route("/lecturer/students/template.<ext>")
@login_required
def download_student_template(ext):
    ext_clean = (ext or "csv").lower()
    if ext_clean == "xlsx":
        xlsx_bytes = generate_sample_xlsx_bytes()
        return Response(
            xlsx_bytes,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": "attachment; filename=student_upload_template.xlsx"},
        )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Full Name", "Matric Number", "GTS Number", "Phone Number"])
    writer.writerow(["Adebayo Oluwaseun", "CSC/2023/001", "GTS-2026-1001", "08031234567"])
    writer.writerow(["Chidinma Okafor", "CSC/2023/002", "GTS-2026-1002", "08059876543"])
    writer.writerow(["Ibrahim Musa", "CSC/2023/003", "GTS-2026-1003", "08023456789"])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=student_upload_template.csv"},
    )


@app.route("/lecturer/classes/<class_id>/students/export.csv")
@login_required
def export_class_students_csv(class_id):
    cls = get_class_by_id(class_id)
    if not cls:
        flash("Class page not found.", "danger")
        return redirect(url_for("index"))

    students = get_students_by_class(class_id)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["S/N", "Full Name", "Matric Number", "GTS Number", "Phone Number"])
    for idx, st in enumerate(students, start=1):
        writer.writerow([
            idx,
            st.get("full_name", ""),
            st.get("matric_number", ""),
            st.get("gts_number", ""),
            st.get("phone_number", ""),
        ])

    filename = f"{(cls.get('course_code') or 'class').replace(' ', '_')}_students.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ==========================================
# ASSIGNMENTS & PROJECTS SCORE SHEET ROUTES
# ==========================================
@app.route("/lecturer/classes/<class_id>/assessments/create", methods=["POST"])
@login_required
def create_assessment(class_id):
    cls = get_class_by_id(class_id)
    if not cls:
        flash("Class page not found.", "danger")
        return redirect(url_for("index"))

    if session.get("user_id") != cls.get("lecturer_id") and session.get("role") != "admin":
        flash("Only the assigned lecturer can create assignments or projects for this class.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="assessments"))

    category = request.form.get("category", "Assignment").strip()
    title = request.form.get("title", "").strip()
    max_score = request.form.get("max_score", "10").strip()
    date_given = request.form.get("date_given", "").strip()
    description = request.form.get("description", "").strip()

    if not title:
        flash("Please provide a title (e.g. 'Assignment 1' or 'Term Project').", "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="assessments"))

    res = create_class_assessment(
        class_id=class_id,
        lecturer_id=cls.get("lecturer_id", ""),
        title=title,
        category=category,
        max_score=max_score,
        date_given=date_given,
        description=description,
    )

    if res["ok"]:
        new_assess = res["assessment"]
        flash(
            f"{new_assess.get('category')} '{new_assess.get('title')}' (Max: {new_assess.get('max_score')} marks) created! You can now record student scores below.",
            "success",
        )
        return redirect(
            url_for("view_class_page", class_id=class_id, tab="assessments", assessment_id=new_assess["id"])
        )
    else:
        flash(res["error"], "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="assessments"))


@app.route("/lecturer/classes/<class_id>/assessments/<assessment_id>/scores/save", methods=["POST"])
@login_required
def save_assessment_scores_route(class_id, assessment_id):
    cls = get_class_by_id(class_id)
    assessment = get_assessment_by_id(assessment_id)
    if not cls or not assessment:
        flash("Assignment or Project not found.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="assessments"))

    if session.get("user_id") != cls.get("lecturer_id") and session.get("role") != "admin":
        flash("Unauthorized action.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="assessments"))

    scores_updates = {}

    # Check if single student quick-score entry was used
    quick_student_id = request.form.get("quick_student_id", "").strip()
    quick_score = request.form.get("quick_score", "").strip()
    if quick_student_id and quick_score != "":
        scores_updates[quick_student_id] = quick_score

    # Also collect any scores from the full student score sheet table
    for key, val in request.form.items():
        if key.startswith("score__"):
            st_id = key[len("score__") :]
            if st_id:
                scores_updates[st_id] = val

    res = save_assessment_scores(assessment_id, scores_updates)
    if res["ok"]:
        flash(
            f"Saved scores for '{assessment.get('title')}' ({res.get('updated_count', 0)} student record(s) graded).",
            "success",
        )
    else:
        flash(res["error"], "danger")

    return redirect(
        url_for("view_class_page", class_id=class_id, tab="assessments", assessment_id=assessment_id)
    )


@app.route("/lecturer/classes/<class_id>/assessments/<assessment_id>/scores/upload", methods=["POST"])
@login_required
def upload_assessment_scores_route(class_id, assessment_id):
    cls = get_class_by_id(class_id)
    assessment = get_assessment_by_id(assessment_id)
    if not cls or not assessment:
        flash("Assignment or Project not found.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="assessments"))

    if session.get("user_id") != cls.get("lecturer_id") and session.get("role") != "admin":
        flash("Unauthorized action.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="assessments"))

    uploaded_file = request.files.get("scores_file")
    if not uploaded_file or not uploaded_file.filename:
        flash("Please select an Excel (.xlsx) or CSV (.csv) score file to upload.", "danger")
        return redirect(
            url_for("view_class_page", class_id=class_id, tab="assessments", assessment_id=assessment_id)
        )

    students = get_students_by_class(class_id)
    parsed = parse_scores_spreadsheet(uploaded_file.filename, uploaded_file.read(), students)
    if not parsed["ok"]:
        flash(parsed["error"], "danger")
        return redirect(
            url_for("view_class_page", class_id=class_id, tab="assessments", assessment_id=assessment_id)
        )

    res = save_assessment_scores(assessment_id, parsed["scores"])
    if res["ok"]:
        matched_count = len(parsed["scores"])
        flash(
            f"Bulk uploaded {matched_count} student score(s) for '{assessment.get('title')}'!",
            "success",
        )
    else:
        flash(res["error"], "danger")

    return redirect(
        url_for("view_class_page", class_id=class_id, tab="assessments", assessment_id=assessment_id)
    )


@app.route("/lecturer/classes/<class_id>/assessments/<assessment_id>/delete", methods=["POST"])
@login_required
def remove_assessment(class_id, assessment_id):
    cls = get_class_by_id(class_id)
    assessment = get_assessment_by_id(assessment_id)
    if not cls or not assessment:
        flash("Assignment or Project not found.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="assessments"))

    if session.get("user_id") != cls.get("lecturer_id") and session.get("role") != "admin":
        flash("Unauthorized action.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="assessments"))

    res = delete_class_assessment(assessment_id)
    if res["ok"]:
        flash(f"Deleted '{assessment.get('title')}' and its scores.", "info")
    else:
        flash(res["error"], "danger")

    return redirect(url_for("view_class_page", class_id=class_id, tab="assessments"))


@app.route("/lecturer/classes/<class_id>/gradebook/export.csv")
@login_required
def export_class_gradebook_csv(class_id):
    cls = get_class_by_id(class_id)
    if not cls:
        flash("Class page not found.", "danger")
        return redirect(url_for("index"))

    students = get_students_by_class(class_id)
    assessments = get_assessments_by_class(class_id)
    totals = enrich_students_with_assessments(students, assessments)

    output = io.StringIO()
    writer = csv.writer(output)

    headers = ["S/N", "Full Name", "Matric Number", "GTS Number", "Phone Number"]
    for a in assessments:
        headers.append(f"{a.get('title')} ({a.get('category')} / {a.get('max_score')})")
    headers.extend([
        f"Assignments Total ({totals['assignment_max_total']})",
        f"Projects Total ({totals['project_max_total']})",
        f"Overall CA Total ({totals['overall_max_total']})",
    ])
    writer.writerow(headers)

    for idx, st in enumerate(students, start=1):
        row = [
            idx,
            st.get("full_name", ""),
            st.get("matric_number", ""),
            st.get("gts_number", ""),
            st.get("phone_number", ""),
        ]
        st_scores = st.get("assessment_scores") or {}
        for a in assessments:
            val = st_scores.get(a.get("id"))
            row.append(val if val is not None else "")
        row.extend([
            st.get("assignment_total", 0),
            st.get("project_total", 0),
            st.get("overall_total", 0),
        ])
        writer.writerow(row)

    filename = f"{(cls.get('course_code') or 'class').replace(' ', '_')}_gradebook_scores.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/lecturer/change-password", methods=["POST"])
@lecturer_required
def lecturer_change_password():
    new_password = request.form.get("new_password", "").strip()
    confirm_password = request.form.get("confirm_password", "").strip()

    if len(new_password) < 6:
        flash("New password must be at least 6 characters long.", "danger")
        return redirect(url_for("lecturer_dashboard"))

    if new_password != confirm_password:
        flash("New password and confirmation do not match.", "danger")
        return redirect(url_for("lecturer_dashboard"))

    res = update_user_fields(
        session.get("user_id"),
        {"password_hash": generate_password_hash(new_password)},
    )
    if res["ok"]:
        flash("Your password has been updated successfully.", "success")
    else:
        flash(res["error"], "danger")

    return redirect(url_for("lecturer_dashboard"))


# ==========================================
# CBT (COMPUTER-BASED TEST) ROUTES (STEP 5)
# ==========================================
@app.route("/lecturer/cbt/template.<ext>")
@login_required
def download_cbt_template(ext):
    """Download a sample Excel (.xlsx) or CSV (.csv) template for CBT Questions."""
    if ext.lower() == "xlsx":
        xlsx_bytes = generate_sample_cbt_xlsx_bytes()
        return Response(
            xlsx_bytes,
            mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": "attachment; filename=cbt_questions_template.xlsx"},
        )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Question", "Option A", "Option B", "Option C", "Option D", "Correct Answer", "Marks"])
    writer.writerow([
        "Which of the following is an example of system software?",
        "Microsoft Word",
        "Windows Operating System",
        "Adobe Photoshop",
        "Google Chrome",
        "B",
        "1",
    ])
    writer.writerow([
        "What is the shortcut key to copy selected text in MS Word?",
        "Ctrl + V",
        "Ctrl + X",
        "Ctrl + C",
        "Ctrl + Z",
        "C",
        "1",
    ])
    writer.writerow([
        "In MS Excel, every formula must begin with which symbol?",
        "#",
        "@",
        "=",
        "&",
        "C",
        "1",
    ])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=cbt_questions_template.csv"},
    )


@app.route("/lecturer/classes/<class_id>/cbt/create", methods=["POST"])
@login_required
def create_class_cbt(class_id):
    cls = get_class_by_id(class_id)
    if not cls:
        flash("Class page not found.", "danger")
        return redirect(url_for("index"))

    if session.get("user_id") != cls.get("lecturer_id") and session.get("role") != "admin":
        flash("Only the assigned lecturer can create CBT tests for this course.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="cbt"))

    title = request.form.get("title", "").strip()
    duration_minutes = request.form.get("duration_minutes", "20").strip()
    total_marks = request.form.get("total_marks", "20").strip()
    instructions = request.form.get("instructions", "").strip()
    open_at = request.form.get("open_at", "").strip()
    close_at = request.form.get("close_at", "").strip()
    is_active = request.form.get("is_active") == "true"
    show_result_immediately = request.form.get("show_result_immediately", "true") == "true"

    uploaded_file = request.files.get("questions_file")
    if not uploaded_file or not uploaded_file.filename:
        flash("Please select an Excel (.xlsx) or CSV (.csv) file containing CBT questions.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="cbt"))

    parsed = parse_cbt_questions_spreadsheet(uploaded_file.filename, uploaded_file.read())
    if not parsed["ok"]:
        flash(parsed["error"], "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="cbt"))

    res = create_cbt_test(
        class_id=class_id,
        lecturer_id=cls.get("lecturer_id", ""),
        title=title,
        duration_minutes=duration_minutes,
        total_marks=total_marks,
        questions=parsed["questions"],
        is_active=is_active,
        open_at=open_at,
        close_at=close_at,
        instructions=instructions,
        show_result_immediately=show_result_immediately,
        sync_to_gradebook=True,
    )

    if res["ok"]:
        cbt = res["cbt_test"]
        flash(
            f"CBT Test '{cbt.get('title')}' created with {cbt.get('question_count')} questions ({cbt.get('total_marks')} marks)!",
            "success",
        )
        return redirect(
            url_for("view_class_page", class_id=class_id, tab="cbt", cbt_id=cbt.get("id"))
        )
    else:
        flash(res["error"], "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="cbt"))


@app.route("/lecturer/classes/<class_id>/cbt/<cbt_id>/toggle", methods=["POST"])
@login_required
def toggle_class_cbt(class_id, cbt_id):
    cls = get_class_by_id(class_id)
    cbt = get_cbt_test_by_id(cbt_id)
    if not cls or not cbt:
        flash("CBT Test not found.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="cbt"))

    if session.get("user_id") != cls.get("lecturer_id") and session.get("role") != "admin":
        flash("Unauthorized action.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="cbt"))

    new_state = not bool(cbt.get("is_active", False))
    res = update_cbt_test_fields(cbt_id, {"is_active": new_state})
    if res["ok"]:
        state_str = "ACTIVATED (OPEN)" if new_state else "DEACTIVATED (CLOSED)"
        flash(
            f"CBT Test '{cbt.get('title')}' has been {state_str}.",
            "success" if new_state else "warning",
        )
    else:
        flash(res["error"], "danger")

    return redirect(url_for("view_class_page", class_id=class_id, tab="cbt", cbt_id=cbt_id))


@app.route("/lecturer/classes/<class_id>/cbt/<cbt_id>/schedule", methods=["POST"])
@login_required
def update_class_cbt_schedule(class_id, cbt_id):
    cls = get_class_by_id(class_id)
    cbt = get_cbt_test_by_id(cbt_id)
    if not cls or not cbt:
        flash("CBT Test not found.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="cbt"))

    if session.get("user_id") != cls.get("lecturer_id") and session.get("role") != "admin":
        flash("Unauthorized action.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="cbt"))

    open_at = request.form.get("open_at", "").strip()
    close_at = request.form.get("close_at", "").strip()
    duration_raw = request.form.get("duration_minutes", str(cbt.get("duration_minutes", 20))).strip()
    is_active = request.form.get("is_active") == "true"
    show_result_immediately = request.form.get("show_result_immediately") == "true"

    try:
        dur_int = max(1, min(300, int(duration_raw)))
    except (ValueError, TypeError):
        dur_int = cbt.get("duration_minutes", 20)

    res = update_cbt_test_fields(
        cbt_id,
        {
            "open_at": open_at[:16].replace(" ", "T") if open_at else "",
            "close_at": close_at[:16].replace(" ", "T") if close_at else "",
            "duration_minutes": dur_int,
            "is_active": is_active,
            "show_result_immediately": show_result_immediately,
        },
    )
    if res["ok"]:
        flash(f"Updated schedule and settings for '{cbt.get('title')}'.", "success")
    else:
        flash(res["error"], "danger")

    return redirect(url_for("view_class_page", class_id=class_id, tab="cbt", cbt_id=cbt_id))


@app.route("/lecturer/classes/<class_id>/cbt/<cbt_id>/questions/upload", methods=["POST"])
@login_required
def upload_class_cbt_questions(class_id, cbt_id):
    """Replace or append CBT questions from an Excel (.xlsx) or CSV (.csv) file."""
    cls = get_class_by_id(class_id)
    cbt = get_cbt_test_by_id(cbt_id)
    if not cls or not cbt:
        flash("CBT Test not found.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="cbt"))

    if session.get("user_id") != cls.get("lecturer_id") and session.get("role") != "admin":
        flash("Unauthorized action.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="cbt"))

    uploaded_file = request.files.get("questions_file")
    if not uploaded_file or not uploaded_file.filename:
        flash("Please select an Excel (.xlsx) or CSV (.csv) file to upload.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="cbt", cbt_id=cbt_id))

    parsed = parse_cbt_questions_spreadsheet(uploaded_file.filename, uploaded_file.read())
    if not parsed["ok"]:
        flash(parsed["error"], "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="cbt", cbt_id=cbt_id))

    mode = request.form.get("upload_mode", "replace")
    if mode == "append":
        combined = list(cbt.get("questions") or []) + parsed["questions"]
        for idx, q in enumerate(combined, start=1):
            q["q_no"] = idx
        new_questions = combined
    else:
        new_questions = parsed["questions"]

    res = update_cbt_test_fields(
        cbt_id,
        {
            "questions": new_questions,
            "question_count": len(new_questions),
        },
    )
    if res["ok"]:
        flash(
            f"Updated questions for '{cbt.get('title')}' (Total: {len(new_questions)} questions)!",
            "success",
        )
    else:
        flash(res["error"], "danger")

    return redirect(url_for("view_class_page", class_id=class_id, tab="cbt", cbt_id=cbt_id))


@app.route("/lecturer/classes/<class_id>/cbt/<cbt_id>/reset-attempt", methods=["POST"])
@login_required
def reset_cbt_attempt_route(class_id, cbt_id):
    cls = get_class_by_id(class_id)
    cbt = get_cbt_test_by_id(cbt_id)
    if not cls or not cbt:
        flash("CBT Test not found.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="cbt"))

    if session.get("user_id") != cls.get("lecturer_id") and session.get("role") != "admin":
        flash("Unauthorized action.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="cbt"))

    student_id = request.form.get("student_id", "").strip()
    res = reset_cbt_student_attempt(cbt_id, student_id)
    if res["ok"]:
        flash("Student's CBT attempt has been reset. They can now retake the test.", "info")
    else:
        flash(res["error"], "danger")

    return redirect(url_for("view_class_page", class_id=class_id, tab="cbt", cbt_id=cbt_id))


@app.route("/lecturer/classes/<class_id>/cbt/<cbt_id>/delete", methods=["POST"])
@login_required
def delete_class_cbt_route(class_id, cbt_id):
    cls = get_class_by_id(class_id)
    cbt = get_cbt_test_by_id(cbt_id)
    if not cls or not cbt:
        flash("CBT Test not found.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="cbt"))

    if session.get("user_id") != cls.get("lecturer_id") and session.get("role") != "admin":
        flash("Unauthorized action.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="cbt"))

    res = delete_cbt_test(cbt_id)
    if res["ok"]:
        flash(f"Deleted CBT Test '{cbt.get('title')}'.", "info")
    else:
        flash(res["error"], "danger")

    return redirect(url_for("view_class_page", class_id=class_id, tab="cbt"))


@app.route("/lecturer/classes/<class_id>/cbt/<cbt_id>/export.csv")
@login_required
def export_cbt_results_csv(class_id, cbt_id):
    cls = get_class_by_id(class_id)
    cbt = get_cbt_test_by_id(cbt_id)
    if not cls or not cbt:
        flash("CBT Test not found.", "danger")
        return redirect(url_for("view_class_page", class_id=class_id, tab="cbt"))

    students = get_students_by_class(class_id)
    subs = cbt.get("submissions") or {}

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "S/N",
        "Full Name",
        "Matric Number",
        "GTS Number",
        "Phone Number",
        "Status",
        "Correct Answers",
        "Total Questions",
        f"Score (/ {cbt.get('total_marks')})",
        "Percentage (%)",
        "Submitted At",
    ])

    for idx, st in enumerate(students, start=1):
        sub = subs.get(st.get("id", ""))
        if sub:
            writer.writerow([
                idx,
                st.get("full_name", ""),
                st.get("matric_number", ""),
                st.get("gts_number", ""),
                st.get("phone_number", ""),
                "Submitted",
                sub.get("correct_count", 0),
                sub.get("total_questions", cbt.get("question_count", 0)),
                sub.get("score", 0),
                sub.get("percentage", 0),
                sub.get("submitted_at", ""),
            ])
        else:
            writer.writerow([
                idx,
                st.get("full_name", ""),
                st.get("matric_number", ""),
                st.get("gts_number", ""),
                st.get("phone_number", ""),
                "Not Taken",
                "",
                cbt.get("question_count", 0),
                "",
                "",
                "",
            ])

    safe_title = "".join(ch if ch.isalnum() else "_" for ch in (cbt.get("title") or "cbt")).strip("_")
    filename = f"{cls.get('course_code', 'course')}_{safe_title}_results.csv"
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/class/<class_code>/cbt/<cbt_id>", methods=["GET", "POST"])
def student_cbt_portal(class_code, cbt_id):
    """
    Student CBT Test Portal:
    - Step 1 (GET or POST action='verify'): Verify student enrollment on the class roster & check if test is open.
    - Step 2 (POST action='submit'): Auto-grade answers, save to Firestore + Gradebook, and display result receipt.
    """
    cls = get_class_by_code(class_code) or get_class_by_id(class_code)
    if not cls:
        flash("Class page not found.", "danger")
        return redirect(url_for("index"))

    cbt = get_cbt_test_by_id(cbt_id)
    if not cbt or cbt.get("class_id") != cls.get("id"):
        flash("CBT Test not found for this course.", "danger")
        return redirect(url_for("public_class_page", class_code=cls["class_code"], tab="cbt"))

    compute_cbt_status(cbt)
    action = request.form.get("action", "") if request.method == "POST" else ""
    verified_student = None
    existing_submission = None

    if request.method == "POST" and action == "verify":
        identifier = request.form.get("identifier", "").strip()
        matches = verify_student_in_class(cls["id"], identifier)
        if not matches:
            flash(
                f"No student matching '{identifier}' was found on the {cls.get('course_code')} class list. Only enrolled students can take this CBT test.",
                "danger",
            )
        else:
            verified_student = matches[0]
            subs = cbt.get("submissions") or {}
            if verified_student.get("id") in subs:
                existing_submission = subs[verified_student["id"]]
            elif not cbt.get("is_open_now"):
                flash(
                    f"This CBT test is currently not open for new attempts ({cbt.get('status_label')}).",
                    "warning",
                )
                verified_student = None

    elif request.method == "POST" and action == "submit":
        student_id = request.form.get("student_id", "").strip()
        verified_student = get_student_by_id(student_id)
        if not verified_student or verified_student.get("class_id") != cls.get("id"):
            flash("Invalid student session. Please verify your GTS or Matric Number again.", "danger")
            return redirect(url_for("student_cbt_portal", class_code=cls["class_code"], cbt_id=cbt_id))

        # Collect submitted answers: q_1, q_2, ...
        submitted_answers = {}
        for key, val in request.form.items():
            if key.startswith("q_"):
                q_no = key[2:]
                submitted_answers[q_no] = val.strip().upper()

        res = submit_cbt_student_attempt(cbt_id, verified_student, submitted_answers)
        if res.get("ok"):
            existing_submission = res["submission"]
            flash("Your CBT test has been submitted and graded successfully!", "success")
        elif res.get("already_submitted"):
            existing_submission = res["submission"]
            flash("You have already submitted this CBT test.", "info")
        else:
            flash(res.get("error", "Could not submit CBT test."), "danger")

    return render_template(
        "cbt_exam.html",
        class_page=cls,
        cbt=cbt,
        verified_student=verified_student,
        existing_submission=existing_submission,
    )


if __name__ == "__main__":
    app.run(debug=True, port=5000)

