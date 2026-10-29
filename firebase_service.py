import csv
from datetime import datetime, timezone
import io
import re
import secrets
import string
import xml.etree.ElementTree as ET
import zipfile
import requests
from werkzeug.security import check_password_hash, generate_password_hash
from config import FIREBASE_CONFIG

PROJECT_ID = FIREBASE_CONFIG["projectId"]
API_KEY = FIREBASE_CONFIG["apiKey"]

FIRESTORE_BASE_URL = (
    f"https://firestore.googleapis.com/v1/projects/{PROJECT_ID}/databases/(default)/documents"
)
AUTH_BASE_URL = "https://identitytoolkit.googleapis.com/v1"


def _to_firestore_value(val):
    if val is None:
        return {"nullValue": None}
    if isinstance(val, bool):
        return {"booleanValue": val}
    if isinstance(val, int):
        return {"integerValue": str(val)}
    if isinstance(val, float):
        return {"doubleValue": val}
    if isinstance(val, str):
        return {"stringValue": val}
    if isinstance(val, list):
        return {"arrayValue": {"values": [_to_firestore_value(v) for v in val]}}
    if isinstance(val, dict):
        return {"mapValue": {"fields": {k: _to_firestore_value(v) for k, v in val.items()}}}
    return {"stringValue": str(val)}


def _from_firestore_value(val_dict):
    if "stringValue" in val_dict:
        return val_dict["stringValue"]
    if "booleanValue" in val_dict:
        return val_dict["booleanValue"]
    if "integerValue" in val_dict:
        return int(val_dict["integerValue"])
    if "doubleValue" in val_dict:
        return float(val_dict["doubleValue"])
    if "nullValue" in val_dict:
        return None
    if "timestampValue" in val_dict:
        return val_dict["timestampValue"]
    if "arrayValue" in val_dict:
        values = val_dict["arrayValue"].get("values", [])
        return [_from_firestore_value(v) for v in values]
    if "mapValue" in val_dict:
        fields = val_dict["mapValue"].get("fields", {})
        return {k: _from_firestore_value(v) for k, v in fields.items()}
    return None


def _from_firestore_doc(doc):
    if not doc or "fields" not in doc:
        return None
    data = {k: _from_firestore_value(v) for k, v in doc["fields"].items()}
    doc_name = doc.get("name", "")
    data["id"] = doc_name.split("/")[-1] if doc_name else ""
    return data


def _firebase_auth_signup(email, password):
    """Attempt to register user in Firebase Authentication (if Email/Password provider is enabled)."""
    url = f"{AUTH_BASE_URL}/accounts:signUp?key={API_KEY}"
    try:
        resp = requests.post(
            url,
            json={"email": email, "password": password, "returnSecureToken": True},
            timeout=8,
        )
        if resp.status_code == 200:
            return {"ok": True, "uid": resp.json().get("localId")}
        err_msg = resp.json().get("error", {}).get("message", "UNKNOWN_ERROR")
        return {"ok": False, "error": err_msg}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def _firebase_auth_signin(email, password):
    """Attempt to sign in via Firebase Authentication REST API."""
    url = f"{AUTH_BASE_URL}/accounts:signInWithPassword?key={API_KEY}"
    try:
        resp = requests.post(
            url,
            json={"email": email, "password": password, "returnSecureToken": True},
            timeout=8,
        )
        if resp.status_code == 200:
            return {"ok": True, "data": resp.json()}
        err_msg = resp.json().get("error", {}).get("message", "UNKNOWN_ERROR")
        return {"ok": False, "error": err_msg}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def list_all_users():
    """Fetch all documents from the 'users' collection in Firestore."""
    url = f"{FIRESTORE_BASE_URL}/users?pageSize=200"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            return []
        docs = resp.json().get("documents", [])
        users = [_from_firestore_doc(d) for d in docs if d]
        return [u for u in users if u is not None]
    except Exception:
        return []


def get_user_by_id(doc_id):
    if not doc_id:
        return None
    url = f"{FIRESTORE_BASE_URL}/users/{doc_id}"
    try:
        resp = requests.get(url, timeout=8)
        if resp.status_code == 200:
            return _from_firestore_doc(resp.json())
        return None
    except Exception:
        return None


def get_user_by_email(email):
    if not email:
        return None
    email_norm = email.strip().lower()
    for user in list_all_users():
        if (user.get("email") or "").strip().lower() == email_norm:
            return user
    return None


def get_user_by_staff_id(staff_id):
    if not staff_id:
        return None
    staff_norm = staff_id.strip().upper()
    for user in list_all_users():
        if (user.get("staff_id") or "").strip().upper() == staff_norm:
            return user
    return None


def create_user(
    full_name,
    email,
    password,
    role="lecturer",
    staff_id="",
    department="",
    phone="",
    created_by="system",
):
    """Create a user in Firebase Auth (if enabled) and store their profile in Firestore."""
    email_clean = email.strip().lower()
    staff_id_clean = staff_id.strip().upper()

    if get_user_by_email(email_clean):
        return {"ok": False, "error": f"A user with email '{email_clean}' already exists."}

    if staff_id_clean and get_user_by_staff_id(staff_id_clean):
        return {"ok": False, "error": f"A user with Staff ID '{staff_id_clean}' already exists."}

    # Try Firebase Auth signup first
    auth_res = _firebase_auth_signup(email_clean, password)
    if not auth_res["ok"] and auth_res["error"] in ("EMAIL_EXISTS",):
        return {"ok": False, "error": "This email is already registered in Firebase Auth."}

    uid = auth_res.get("uid") or ""
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    user_doc = {
        "full_name": full_name.strip(),
        "email": email_clean,
        "password_hash": generate_password_hash(password),
        "role": role.strip().lower(),
        "staff_id": staff_id_clean,
        "department": department.strip(),
        "phone": phone.strip(),
        "status": "active",
        "auth_uid": uid,
        "created_at": now_iso,
        "created_by": created_by,
    }

    fields = {k: _to_firestore_value(v) for k, v in user_doc.items()}
    url = f"{FIRESTORE_BASE_URL}/users"
    if uid:
        url = f"{FIRESTORE_BASE_URL}/users?documentId={uid}"

    try:
        resp = requests.post(url, json={"fields": fields}, timeout=10)
        if resp.status_code in (200, 201):
            created = _from_firestore_doc(resp.json())
            return {"ok": True, "user": created}
        return {"ok": False, "error": f"Firestore error ({resp.status_code}): {resp.text}"}
    except Exception as exc:
        return {"ok": False, "error": f"Failed to connect to Firebase: {exc}"}


def authenticate_user(identifier, password, expected_role=None):
    """
    Authenticate an Admin or Lecturer using either Email or Staff ID + password.
    Verifies against Firebase Auth (when enabled) and Firestore password hash.
    """
    identifier_clean = (identifier or "").strip()
    if not identifier_clean or not password:
        return {"ok": False, "error": "Please enter both your email/Staff ID and password."}

    if "@" in identifier_clean:
        user = get_user_by_email(identifier_clean)
    else:
        user = get_user_by_staff_id(identifier_clean)
        if not user:
            user = get_user_by_email(identifier_clean)

    if not user:
        return {"ok": False, "error": "Invalid credentials. User account not found."}

    if user.get("status", "active") != "active":
        return {
            "ok": False,
            "error": "Your account has been deactivated. Please contact the Administrator.",
        }

    if expected_role and user.get("role") != expected_role:
        role_label = "Administrator" if expected_role == "admin" else "Lecturer"
        return {
            "ok": False,
            "error": f"Access denied. This account is not registered as a {role_label}.",
        }

    # Verify password against Firestore hash or Firebase Auth
    password_hash = user.get("password_hash", "")
    hash_valid = bool(password_hash and check_password_hash(password_hash, password))

    if not hash_valid:
        # Also check Firebase Auth in case password was changed via Firebase console
        auth_res = _firebase_auth_signin(user.get("email", ""), password)
        if not auth_res["ok"]:
            return {"ok": False, "error": "Invalid password. Please try again."}

    return {"ok": True, "user": user}


def get_all_lecturers():
    users = list_all_users()
    lecturers = [u for u in users if u.get("role") == "lecturer"]
    lecturers.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return lecturers


def get_all_admins():
    users = list_all_users()
    return [u for u in users if u.get("role") == "admin"]


def update_user_fields(doc_id, updates):
    """Patch specific fields on a Firestore user document."""
    if not doc_id or not updates:
        return {"ok": False, "error": "Invalid update parameters."}

    mask_params = "&".join([f"updateMask.fieldPaths={k}" for k in updates.keys()])
    url = f"{FIRESTORE_BASE_URL}/users/{doc_id}?{mask_params}"
    fields = {k: _to_firestore_value(v) for k, v in updates.items()}

    try:
        resp = requests.patch(url, json={"fields": fields}, timeout=10)
        if resp.status_code == 200:
            return {"ok": True, "user": _from_firestore_doc(resp.json())}
        return {"ok": False, "error": f"Failed to update user ({resp.status_code})."}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def delete_user(doc_id):
    if not doc_id:
        return {"ok": False, "error": "Missing user ID."}
    url = f"{FIRESTORE_BASE_URL}/users/{doc_id}"
    try:
        resp = requests.delete(url, timeout=10)
        if resp.status_code in (200, 204):
            return {"ok": True}
        return {"ok": False, "error": f"Failed to delete user ({resp.status_code})."}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def ensure_default_admin():
    """Ensure at least one Admin user exists in Firestore so the system can be logged into immediately."""
    admins = get_all_admins()
    if admins:
        return admins[0]

    res = create_user(
        full_name="System Administrator",
        email="admin@schoolrec.edu",
        password="Admin@123",
        role="admin",
        staff_id="ADM-001",
        department="Central Administration",
        phone="+234 800 000 0001",
        created_by="system_bootstrap",
    )
    return res.get("user")


# ==========================================
# CLASS PAGES & LECTURE SESSIONS (STEP 2)
# ==========================================
def _generate_class_code(course_code):
    prefix = "".join(ch for ch in (course_code or "CLS").upper() if ch.isalnum())[:6]
    if not prefix:
        prefix = "CLS"
    alphabet = string.ascii_uppercase + string.digits
    suffix = "".join(secrets.choice(alphabet) for _ in range(4))
    return f"{prefix}-{suffix}"


def list_all_classes():
    """Fetch all documents from the 'classes' collection in Firestore."""
    url = f"{FIRESTORE_BASE_URL}/classes?pageSize=200"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            return []
        docs = resp.json().get("documents", [])
        classes = [_from_firestore_doc(d) for d in docs if d]
        result = [c for c in classes if c is not None]
        result.sort(key=lambda x: x.get("created_at", ""), reverse=True)
        return result
    except Exception:
        return []


def get_classes_by_lecturer(lecturer_id):
    if not lecturer_id:
        return []
    return [c for c in list_all_classes() if c.get("lecturer_id") == lecturer_id]


def get_class_by_id(class_id):
    if not class_id:
        return None
    url = f"{FIRESTORE_BASE_URL}/classes/{class_id}"
    try:
        resp = requests.get(url, timeout=8)
        if resp.status_code == 200:
            return _from_firestore_doc(resp.json())
        return None
    except Exception:
        return None


def get_class_by_code(class_code):
    if not class_code:
        return None
    code_norm = class_code.strip().upper()
    for cls in list_all_classes():
        if (cls.get("class_code") or "").strip().upper() == code_norm:
            return cls
    return None


def create_class_page(
    lecturer_id,
    lecturer_name,
    lecturer_email,
    lecturer_staff_id,
    department,
    course_code,
    course_title,
    level,
    semester,
    academic_session,
    credit_units=3,
    schedule="",
    venue="",
    description="",
):
    """Create a new Lecturer Class Page in Firestore."""
    course_code_clean = course_code.strip().upper()
    course_title_clean = course_title.strip()

    # Check if this lecturer already has a class with the same course code and session
    existing_classes = get_classes_by_lecturer(lecturer_id)
    for cls in existing_classes:
        if (
            (cls.get("course_code") or "").strip().upper() == course_code_clean
            and (cls.get("academic_session") or "").strip() == academic_session.strip()
        ):
            return {
                "ok": False,
                "error": f"You already have a class page for {course_code_clean} in {academic_session}.",
            }

    class_code = _generate_class_code(course_code_clean)
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    try:
        units_int = int(credit_units)
    except (ValueError, TypeError):
        units_int = 3

    class_doc = {
        "lecturer_id": lecturer_id,
        "lecturer_name": lecturer_name.strip(),
        "lecturer_email": lecturer_email.strip().lower(),
        "lecturer_staff_id": (lecturer_staff_id or "").strip().upper(),
        "department": (department or "").strip(),
        "course_code": course_code_clean,
        "course_title": course_title_clean,
        "level": (level or "100 Level").strip(),
        "semester": (semester or "First Semester").strip(),
        "academic_session": (academic_session or "2025/2026").strip(),
        "credit_units": units_int,
        "schedule": (schedule or "").strip(),
        "venue": (venue or "").strip(),
        "description": (description or "").strip(),
        "class_code": class_code,
        "allow_self_registration": False,
        "status": "active",
        "created_at": now_iso,
    }

    fields = {k: _to_firestore_value(v) for k, v in class_doc.items()}
    url = f"{FIRESTORE_BASE_URL}/classes"

    try:
        resp = requests.post(url, json={"fields": fields}, timeout=10)
        if resp.status_code in (200, 201):
            created = _from_firestore_doc(resp.json())
            return {"ok": True, "class_page": created}
        return {"ok": False, "error": f"Firestore error ({resp.status_code}): {resp.text}"}
    except Exception as exc:
        return {"ok": False, "error": f"Failed to connect to Firebase: {exc}"}


def update_class_fields(class_id, updates):
    """Patch specific fields on a Firestore class document."""
    if not class_id or not updates:
        return {"ok": False, "error": "Invalid update parameters."}

    mask_params = "&".join([f"updateMask.fieldPaths={k}" for k in updates.keys()])
    url = f"{FIRESTORE_BASE_URL}/classes/{class_id}?{mask_params}"
    fields = {k: _to_firestore_value(v) for k, v in updates.items()}

    try:
        resp = requests.patch(url, json={"fields": fields}, timeout=10)
        if resp.status_code == 200:
            return {"ok": True, "class_page": _from_firestore_doc(resp.json())}
        return {"ok": False, "error": f"Failed to update class page ({resp.status_code})."}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def delete_class_page(class_id):
    if not class_id:
        return {"ok": False, "error": "Missing class ID."}
    url = f"{FIRESTORE_BASE_URL}/classes/{class_id}"
    try:
        resp = requests.delete(url, timeout=10)
        if resp.status_code in (200, 204):
            # Also delete associated sessions, assessments, and students for this class
            for sess in get_sessions_by_class(class_id):
                delete_lecture_session(sess.get("id"))
            for assess in get_assessments_by_class(class_id):
                delete_class_assessment(assess.get("id"))
            clear_class_students(class_id)
            return {"ok": True}
        return {"ok": False, "error": f"Failed to delete class page ({resp.status_code})."}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def list_all_sessions():
    """Fetch all lecture session records from 'lecture_sessions' collection."""
    url = f"{FIRESTORE_BASE_URL}/lecture_sessions?pageSize=300"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            return []
        docs = resp.json().get("documents", [])
        sessions = [_from_firestore_doc(d) for d in docs if d]
        result = [s for s in sessions if s is not None]
        result.sort(key=lambda x: (x.get("lecture_date", ""), x.get("created_at", "")), reverse=True)
        return result
    except Exception:
        return []


def get_sessions_by_class(class_id):
    if not class_id:
        return []
    return [s for s in list_all_sessions() if s.get("class_id") == class_id]


def get_session_by_id(session_id):
    if not session_id:
        return None
    url = f"{FIRESTORE_BASE_URL}/lecture_sessions/{session_id}"
    try:
        resp = requests.get(url, timeout=8)
        if resp.status_code == 200:
            return _from_firestore_doc(resp.json())
        return None
    except Exception:
        return None


def create_lecture_session(
    class_id,
    lecturer_id,
    week_number,
    topic,
    lecture_date,
    start_time="",
    end_time="",
    venue="",
    attendance_count=0,
    summary="",
    materials_link="",
):
    """Log a lecture session / class record inside a Class Page."""
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    try:
        week_int = int(week_number)
    except (ValueError, TypeError):
        week_int = 1

    try:
        att_int = int(attendance_count)
    except (ValueError, TypeError):
        att_int = 0

    sess_doc = {
        "class_id": class_id,
        "lecturer_id": lecturer_id,
        "week_number": week_int,
        "topic": topic.strip(),
        "lecture_date": lecture_date.strip(),
        "start_time": start_time.strip(),
        "end_time": end_time.strip(),
        "venue": venue.strip(),
        "attendance_count": att_int,
        "summary": summary.strip(),
        "materials_link": materials_link.strip(),
        "created_at": now_iso,
    }

    fields = {k: _to_firestore_value(v) for k, v in sess_doc.items()}
    url = f"{FIRESTORE_BASE_URL}/lecture_sessions"

    try:
        resp = requests.post(url, json={"fields": fields}, timeout=10)
        if resp.status_code in (200, 201):
            return {"ok": True, "session": _from_firestore_doc(resp.json())}
        return {"ok": False, "error": f"Firestore error ({resp.status_code}): {resp.text}"}
    except Exception as exc:
        return {"ok": False, "error": f"Failed to save lecture session: {exc}"}


def delete_lecture_session(session_id):
    if not session_id:
        return {"ok": False, "error": "Missing session ID."}
    url = f"{FIRESTORE_BASE_URL}/lecture_sessions/{session_id}"
    try:
        resp = requests.delete(url, timeout=8)
        if resp.status_code in (200, 204):
            return {"ok": True}
        return {"ok": False, "error": f"Failed to delete lecture session ({resp.status_code})."}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


# ==========================================
# CLASS STUDENTS & EXCEL/CSV UPLOAD (STEP 3)
# ==========================================
_PLACEHOLDER_IDS = {
    "",
    "NOT AVAILABLE",
    "NOT AVALABLE",
    "NOT AVIALABLE",
    "UNAVAILABLE",
    "NA",
    "N/A",
    "N A",
    "NONE",
    "NIL",
    "NULL",
    "-",
    "--",
    "PENDING",
    "UNKNOWN",
    "NO MATRIC",
    "NO MATRIC NUMBER",
}


def _is_valid_id(val):
    if not val:
        return False
    cleaned = re.sub(r"\s+", " ", str(val)).strip().upper()
    if cleaned in _PLACEHOLDER_IDS:
        return False
    if "NOT AVA" in cleaned or "UNAVAIL" in cleaned or "NO MATRIC" in cleaned:
        return False
    # Must contain at least one digit or alphanumeric identifier
    alnum = re.sub(r"[^A-Z0-9]+", "", cleaned)
    return len(alnum) >= 3


def _make_student_doc_id(class_id, full_name="", matric_number="", gts_number="", phone_number=""):
    """
    Build a unique Firestore document ID for a student in a class.
    Handles cases where Matric Number is 'NOT AVALABLE' / 'N/A' by falling back to GTS Number and Name/Phone.
    """
    name_key = re.sub(r"[^A-Z0-9]+", "_", (full_name or "").strip().upper()).strip("_")[:24]
    phone_key = re.sub(r"[^0-9]+", "", (phone_number or "").strip())[-10:]

    if _is_valid_id(matric_number):
        id_key = re.sub(r"[^A-Z0-9]+", "_", matric_number.strip().upper()).strip("_")
        clean_key = f"M_{id_key}"
    elif _is_valid_id(gts_number):
        # Normalize spaces in GTS numbers e.g. 'Gts 2611359' -> 'GTS2611359'
        id_key = re.sub(r"[^A-Z0-9]+", "", gts_number.strip().upper())[:24]
        clean_key = f"G_{id_key}_{name_key[:12]}" if name_key else f"G_{id_key}"
    elif name_key or phone_key:
        clean_key = f"N_{name_key}_{phone_key}".strip("_")
    else:
        clean_key = secrets.token_hex(6)

    return f"{class_id}__{clean_key}"


def list_all_class_students():
    """Fetch all documents from the 'class_students' collection in Firestore with pagination."""
    students = []
    page_token = None
    try:
        while True:
            url = f"{FIRESTORE_BASE_URL}/class_students?pageSize=300"
            if page_token:
                url += f"&pageToken={page_token}"
            resp = requests.get(url, timeout=12)
            if resp.status_code != 200:
                break
            data = resp.json()
            docs = data.get("documents", [])
            for d in docs:
                if d:
                    parsed = _from_firestore_doc(d)
                    if parsed is not None:
                        students.append(parsed)
            page_token = data.get("nextPageToken")
            if not page_token:
                break
        students.sort(key=lambda x: (x.get("full_name") or "").lower())
        return students
    except Exception:
        return students


def get_students_by_class(class_id):
    if not class_id:
        return []
    class_students = [s for s in list_all_class_students() if s.get("class_id") == class_id]
    for idx, st in enumerate(class_students, start=1):
        st["serial_no"] = idx
        st["has_valid_matric"] = _is_valid_id(st.get("matric_number", ""))
    return class_students


def verify_student_in_class(class_id, query):
    """
    Search for a student in a class by GTS Number, Matric Number, Phone Number, or Full Name.
    Returns matching student records with their serial number on the class roster.
    """
    q_raw = (query or "").strip()
    if not q_raw or len(q_raw) < 3:
        return []

    q_upper = q_raw.upper()
    q_alnum = re.sub(r"[^A-Z0-9]+", "", q_upper)
    q_digits = re.sub(r"[^0-9]+", "", q_raw)

    students = get_students_by_class(class_id)
    exact_matches = []
    partial_matches = []

    for st in students:
        gts_raw = (st.get("gts_number") or "").strip().upper()
        gts_alnum = re.sub(r"[^A-Z0-9]+", "", gts_raw)
        gts_digits = re.sub(r"[^0-9]+", "", gts_raw)

        matric_raw = (st.get("matric_number") or "").strip().upper()
        matric_alnum = re.sub(r"[^A-Z0-9]+", "", matric_raw) if _is_valid_id(matric_raw) else ""

        phone_raw = (st.get("phone_number") or "").strip()
        phone_digits = re.sub(r"[^0-9]+", "", phone_raw)

        name_raw = (st.get("full_name") or "").strip().upper()

        # 1. Exact ID or Phone match
        if q_alnum and (
            (gts_alnum and q_alnum == gts_alnum)
            or (matric_alnum and q_alnum == matric_alnum)
            or (gts_digits and len(q_digits) >= 6 and q_digits == gts_digits)
        ):
            exact_matches.append(st)
            continue

        if q_digits and len(q_digits) >= 7 and phone_digits:
            if q_digits[-9:] == phone_digits[-9:]:
                exact_matches.append(st)
                continue

        if q_upper == name_raw:
            exact_matches.append(st)
            continue

        # 2. Partial match on Name, GTS, or Matric
        if (
            (len(q_upper) >= 3 and q_upper in name_raw)
            or (q_alnum and len(q_alnum) >= 4 and (q_alnum in gts_alnum or (matric_alnum and q_alnum in matric_alnum)))
        ):
            partial_matches.append(st)

    return exact_matches if exact_matches else partial_matches


def student_self_update_matric(class_id, student_id, verification_token, new_matric_number):
    """
    Allow a verified student on the public class page to update their Matric Number
    after confirming their GTS Number or Phone Number.
    """
    student = get_student_by_id(student_id)
    if not student or student.get("class_id") != class_id:
        return {"ok": False, "error": "Student record not found in this class."}

    new_matric_clean = re.sub(r"\s+", " ", (new_matric_number or "")).strip().upper()
    if not _is_valid_id(new_matric_clean):
        return {"ok": False, "error": "Please enter a valid Matric Number."}

    token_clean = (verification_token or "").strip().upper()
    token_alnum = re.sub(r"[^A-Z0-9]+", "", token_clean)
    token_digits = re.sub(r"[^0-9]+", "", token_clean)

    st_gts_alnum = re.sub(r"[^A-Z0-9]+", "", (student.get("gts_number") or "").upper())
    st_gts_digits = re.sub(r"[^0-9]+", "", (student.get("gts_number") or ""))
    st_phone_digits = re.sub(r"[^0-9]+", "", (student.get("phone_number") or ""))

    verified = False
    if token_alnum and st_gts_alnum and (token_alnum == st_gts_alnum or (len(token_digits) >= 5 and token_digits == st_gts_digits)):
        verified = True
    elif token_digits and len(token_digits) >= 4 and st_phone_digits and st_phone_digits.endswith(token_digits[-4:]):
        verified = True

    if not verified:
        return {
            "ok": False,
            "error": "Verification failed. Please enter your matching GTS Number or Phone Number to update your Matric Number.",
        }

    # Ensure no other student in this class already has this Matric Number
    for other in get_students_by_class(class_id):
        if other.get("id") != student_id:
            other_mat = re.sub(r"[^A-Z0-9]+", "", (other.get("matric_number") or "").upper())
            if _is_valid_id(other.get("matric_number")) and other_mat == re.sub(r"[^A-Z0-9]+", "", new_matric_clean):
                return {
                    "ok": False,
                    "error": f"Matric Number '{new_matric_clean}' is already registered to another student in this class.",
                }

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    res = update_student_fields(
        student_id,
        {
            "matric_number": new_matric_clean,
            "matric_updated_at": now_iso,
        },
    )
    if res["ok"]:
        return {"ok": True, "student": res["student"]}
    return res


def student_self_register_in_class(
    class_id,
    full_name,
    matric_number,
    gts_number,
    phone_number,
):
    """
    Allow a student on the public class page to add their own record to the class roster
    ONLY when the lecturer has activated `allow_self_registration` on the class.
    Includes duplicate detection against existing GTS Number, Matric Number, or Full Name.
    """
    cls = get_class_by_id(class_id)
    if not cls:
        return {"ok": False, "error": "Class page not found."}

    if not cls.get("allow_self_registration", False):
        return {
            "ok": False,
            "error": "Student self-registration is currently deactivated by the lecturer for this course.",
        }

    full_name_clean = re.sub(r"\s+", " ", (full_name or "")).strip().upper()
    gts_clean = re.sub(r"\s+", "", (gts_number or "")).strip().upper()
    matric_clean = re.sub(r"\s+", " ", (matric_number or "")).strip().upper()
    phone_clean = re.sub(r"\s+", " ", (phone_number or "")).strip()

    if not full_name_clean or len(full_name_clean) < 3:
        return {"ok": False, "error": "Please enter your complete Full Name (Surname first)."}

    if not _is_valid_id(gts_clean) and not _is_valid_id(matric_clean):
        return {
            "ok": False,
            "error": "Please provide a valid GTS Number or Matric Number.",
        }

    if not phone_clean or len(re.sub(r"[^0-9]+", "", phone_clean)) < 7:
        return {"ok": False, "error": "Please provide a valid Phone Number."}

    if not _is_valid_id(matric_clean):
        matric_clean = "NOT AVAILABLE"

    # Check if student is already on the class list to prevent duplicates
    existing_students = get_students_by_class(class_id)
    new_gts_alnum = re.sub(r"[^A-Z0-9]+", "", gts_clean)
    new_gts_digits = re.sub(r"[^0-9]+", "", gts_clean)
    new_mat_alnum = re.sub(r"[^A-Z0-9]+", "", matric_clean) if _is_valid_id(matric_clean) else ""

    for st in existing_students:
        st_gts_alnum = re.sub(r"[^A-Z0-9]+", "", (st.get("gts_number") or "").upper())
        st_gts_digits = re.sub(r"[^0-9]+", "", (st.get("gts_number") or ""))
        st_mat_raw = (st.get("matric_number") or "").upper()
        st_mat_alnum = re.sub(r"[^A-Z0-9]+", "", st_mat_raw) if _is_valid_id(st_mat_raw) else ""
        st_name = re.sub(r"\s+", " ", (st.get("full_name") or "")).strip().upper()

        if new_gts_alnum and st_gts_alnum and (
            new_gts_alnum == st_gts_alnum
            or (len(new_gts_digits) >= 6 and new_gts_digits == st_gts_digits)
        ):
            return {
                "ok": False,
                "already_exists": True,
                "student": st,
                "error": f"Your GTS Number ({st.get('gts_number')}) is already on the class list under '{st.get('full_name')}' (Roster #{st.get('serial_no')}).",
            }

        if new_mat_alnum and st_mat_alnum and new_mat_alnum == st_mat_alnum:
            return {
                "ok": False,
                "already_exists": True,
                "student": st,
                "error": f"Matric Number '{matric_clean}' is already registered on the class list under '{st.get('full_name')}' (Roster #{st.get('serial_no')}).",
            }

        if full_name_clean == st_name:
            return {
                "ok": False,
                "already_exists": True,
                "student": st,
                "error": f"'{st.get('full_name')}' is already on the class list (Roster #{st.get('serial_no')}).",
            }

    res = add_student_to_class(
        class_id=class_id,
        lecturer_id=cls.get("lecturer_id", ""),
        full_name=full_name_clean,
        matric_number=matric_clean,
        gts_number=gts_clean,
        phone_number=phone_clean,
    )
    if res["ok"]:
        return {
            "ok": True,
            "query_key": gts_clean if _is_valid_id(gts_clean) else full_name_clean,
        }
    return res


def get_student_by_id(student_id):
    if not student_id:
        return None
    url = f"{FIRESTORE_BASE_URL}/class_students/{student_id}"
    try:
        resp = requests.get(url, timeout=8)
        if resp.status_code == 200:
            return _from_firestore_doc(resp.json())
        return None
    except Exception:
        return None


def add_student_to_class(
    class_id,
    lecturer_id,
    full_name,
    matric_number,
    gts_number,
    phone_number="",
):
    """Add or update a single student record in a class."""
    full_name_clean = (full_name or "").strip()
    matric_clean = (matric_number or "").strip().upper()
    gts_clean = (gts_number or "").strip().upper()
    phone_clean = (phone_number or "").strip()

    if not full_name_clean:
        return {"ok": False, "error": "Student Full Name is required."}

    res = bulk_upsert_students(
        class_id=class_id,
        lecturer_id=lecturer_id,
        students_list=[
            {
                "full_name": full_name_clean,
                "matric_number": matric_clean or "NOT AVAILABLE",
                "gts_number": gts_clean,
                "phone_number": phone_clean,
            }
        ],
    )
    if res["ok"]:
        return {"ok": True, "count": res.get("count", 1)}
    return res


def bulk_upsert_students(class_id, lecturer_id, students_list):
    """
    Fast batch write of students into Firestore 'class_students' collection using :commit.
    Handles placeholder Matric Numbers ('NOT AVALABLE', 'N/A', etc.) by keying on GTS Number + Name.
    """
    if not class_id or not students_list:
        return {"ok": False, "error": "No valid student records found to upload."}

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    writes = []
    seen_doc_ids = set()

    for item in students_list:
        full_name = re.sub(r"\s+", " ", str(item.get("full_name") or "")).strip()
        matric_number = re.sub(r"\s+", " ", str(item.get("matric_number") or "")).strip().upper()
        gts_number = re.sub(r"\s+", " ", str(item.get("gts_number") or "")).strip().upper()
        phone_number = re.sub(r"\s+", " ", str(item.get("phone_number") or "")).strip()

        if not full_name and not matric_number and not gts_number:
            continue

        doc_id = _make_student_doc_id(
            class_id=class_id,
            full_name=full_name,
            matric_number=matric_number,
            gts_number=gts_number,
            phone_number=phone_number,
        )
        if doc_id in seen_doc_ids:
            continue
        seen_doc_ids.add(doc_id)

        doc_path = f"projects/{PROJECT_ID}/databases/(default)/documents/class_students/{doc_id}"
        student_doc = {
            "class_id": class_id,
            "lecturer_id": lecturer_id,
            "full_name": full_name,
            "matric_number": matric_number or "NOT AVAILABLE",
            "gts_number": gts_number,
            "phone_number": phone_number,
            "created_at": now_iso,
        }
        writes.append(
            {
                "update": {
                    "name": doc_path,
                    "fields": {k: _to_firestore_value(v) for k, v in student_doc.items()},
                }
            }
        )

    if not writes:
        return {"ok": False, "error": "No valid student rows found in the uploaded data."}

    commit_url = f"{FIRESTORE_BASE_URL}:commit"
    try:
        # Firestore :commit supports up to 500 writes per request
        for i in range(0, len(writes), 450):
            batch = writes[i : i + 450]
            resp = requests.post(commit_url, json={"writes": batch}, timeout=15)
            if resp.status_code != 200:
                return {
                    "ok": False,
                    "error": f"Firestore batch commit failed ({resp.status_code}): {resp.text}",
                }
        return {"ok": True, "count": len(writes)}
    except Exception as exc:
        return {"ok": False, "error": f"Failed to save student records: {exc}"}


def update_student_fields(student_id, updates):
    if not student_id or not updates:
        return {"ok": False, "error": "Invalid student update parameters."}

    mask_params = "&".join([f"updateMask.fieldPaths={k}" for k in updates.keys()])
    url = f"{FIRESTORE_BASE_URL}/class_students/{student_id}?{mask_params}"
    fields = {k: _to_firestore_value(v) for k, v in updates.items()}

    try:
        resp = requests.patch(url, json={"fields": fields}, timeout=10)
        if resp.status_code == 200:
            return {"ok": True, "student": _from_firestore_doc(resp.json())}
        return {"ok": False, "error": f"Failed to update student ({resp.status_code})."}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def delete_student(student_id):
    if not student_id:
        return {"ok": False, "error": "Missing student ID."}
    url = f"{FIRESTORE_BASE_URL}/class_students/{student_id}"
    try:
        resp = requests.delete(url, timeout=8)
        if resp.status_code in (200, 204):
            return {"ok": True}
        return {"ok": False, "error": f"Failed to delete student ({resp.status_code})."}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def clear_class_students(class_id):
    """Remove all students belonging to a specific class in a single batch commit."""
    students = get_students_by_class(class_id)
    if not students:
        return {"ok": True, "deleted": 0}

    writes = [
        {
            "delete": f"projects/{PROJECT_ID}/databases/(default)/documents/class_students/{s['id']}"
        }
        for s in students
        if s.get("id")
    ]
    commit_url = f"{FIRESTORE_BASE_URL}:commit"
    try:
        for i in range(0, len(writes), 450):
            requests.post(commit_url, json={"writes": writes[i : i + 450]}, timeout=12)
        return {"ok": True, "deleted": len(writes)}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


# ==========================================
# EXCEL (.XLSX) & CSV PARSER AND GENERATOR
# ==========================================
def _col_letters_to_index(col_str):
    idx = 0
    for ch in col_str:
        if "A" <= ch <= "Z":
            idx = idx * 26 + (ord(ch) - ord("A") + 1)
    return max(idx - 1, 0)


def _parse_xlsx_bytes(file_bytes):
    """
    Parse an Excel .xlsx file using Python's built-in zipfile + ElementTree
    (no external C-dependencies needed on Vercel).
    """
    rows = []
    with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
        shared_strings = []
        if "xl/sharedStrings.xml" in zf.namelist():
            ss_xml = zf.read("xl/sharedStrings.xml")
            ss_root = ET.fromstring(ss_xml)
            for si in ss_root.iter():
                if si.tag.endswith("}si") or si.tag == "si":
                    texts = [
                        t.text or ""
                        for t in si.iter()
                        if t.tag.endswith("}t") or t.tag == "t"
                    ]
                    shared_strings.append("".join(texts))

        # Locate the first worksheet
        sheet_names = sorted(
            name for name in zf.namelist() if name.startswith("xl/worksheets/sheet") and name.endswith(".xml")
        )
        if not sheet_names:
            return []

        sheet_xml = zf.read(sheet_names[0])
        sheet_root = ET.fromstring(sheet_xml)

        for elem in sheet_root.iter():
            if elem.tag.endswith("}row") or elem.tag == "row":
                row_cells = {}
                max_col = -1
                for cell in elem:
                    if not (cell.tag.endswith("}c") or cell.tag == "c"):
                        continue
                    ref = cell.attrib.get("r", "")
                    col_letters = "".join(ch for ch in ref if ch.isalpha()).upper()
                    col_idx = _col_letters_to_index(col_letters) if col_letters else (max_col + 1)
                    max_col = max(max_col, col_idx)

                    cell_type = cell.attrib.get("t", "")
                    val_str = ""
                    if cell_type == "inlineStr":
                        texts = [
                            t.text or ""
                            for t in cell.iter()
                            if t.tag.endswith("}t") or t.tag == "t"
                        ]
                        val_str = "".join(texts)
                    else:
                        v_elem = None
                        for child in cell:
                            if child.tag.endswith("}v") or child.tag == "v":
                                v_elem = child
                                break
                        raw_val = v_elem.text if (v_elem is not None and v_elem.text is not None) else ""
                        if cell_type == "s":
                            try:
                                ss_idx = int(raw_val)
                                val_str = shared_strings[ss_idx] if 0 <= ss_idx < len(shared_strings) else ""
                            except (ValueError, TypeError):
                                val_str = raw_val
                        else:
                            val_str = raw_val

                    row_cells[col_idx] = str(val_str).strip()

                if max_col >= 0:
                    row_list = [row_cells.get(i, "") for i in range(max_col + 1)]
                    if any(cell_val.strip() for cell_val in row_list):
                        rows.append(row_list)
    return rows


def _parse_csv_bytes(file_bytes):
    text = None
    for enc in ("utf-8-sig", "utf-8", "cp1252", "latin-1"):
        try:
            text = file_bytes.decode(enc)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        text = file_bytes.decode("utf-8", errors="replace")

    if not text.strip():
        return []

    first_lines = [line for line in text.splitlines()[:5] if line.strip()]
    sample = "\n".join(first_lines)
    delimiter = ","
    if "\t" in sample and sample.count("\t") >= sample.count(","):
        delimiter = "\t"
    elif ";" in sample and sample.count(";") > sample.count(","):
        delimiter = ";"

    reader = csv.reader(io.StringIO(text), delimiter=delimiter)
    return [
        [re.sub(r"\s+", " ", str(c)).strip() for c in row]
        for row in reader
        if any(str(c).strip() for c in row)
    ]


def parse_students_spreadsheet(filename, file_bytes):
    """
    Parse an uploaded Excel (.xlsx) or CSV (.csv) file containing student records:
    Columns: Full Name, Matric Number, GTS Number, Phone Number
    """
    fname_lower = (filename or "").lower()
    if not file_bytes:
        return {"ok": False, "error": "The uploaded file is empty."}

    try:
        if fname_lower.endswith(".xlsx") or file_bytes[:2] == b"PK":
            raw_rows = _parse_xlsx_bytes(file_bytes)
        elif fname_lower.endswith(".csv") or fname_lower.endswith(".txt"):
            raw_rows = _parse_csv_bytes(file_bytes)
        else:
            return {
                "ok": False,
                "error": "Unsupported file format. Please upload an Excel (.xlsx) or CSV (.csv) file.",
            }
    except Exception as exc:
        return {"ok": False, "error": f"Could not read spreadsheet file: {exc}"}

    if not raw_rows:
        return {"ok": False, "error": "No data rows found in the uploaded file."}

    # Detect header row vs data row
    first_row_norm = [re.sub(r"[^a-z0-9]+", " ", c.lower()).strip() for c in raw_rows[0]]
    header_keywords = {"name", "full name", "matric", "matric number", "gts", "gts number", "phone", "phone number"}
    has_header = any(
        any(kw in cell for kw in header_keywords)
        for cell in first_row_norm
        if cell
    )

    col_map = {"full_name": 0, "matric_number": 1, "gts_number": 2, "phone_number": 3}
    start_idx = 0

    if has_header:
        start_idx = 1
        detected = {}
        for idx, cell in enumerate(first_row_norm):
            if not cell:
                continue
            if ("name" in cell or "student" in cell or "surname" in cell) and "full_name" not in detected:
                detected["full_name"] = idx
            elif ("matric" in cell or "mat no" in cell or "reg" in cell) and "matric_number" not in detected:
                detected["matric_number"] = idx
            elif "gts" in cell and "gts_number" not in detected:
                detected["gts_number"] = idx
            elif ("phone" in cell or "mobile" in cell or "tel" in cell or "contact" in cell) and "phone_number" not in detected:
                detected["phone_number"] = idx

        if "full_name" in detected and "matric_number" in detected:
            col_map.update(detected)

    students = []
    for row in raw_rows[start_idx:]:
        def _get_col(key):
            pos = col_map.get(key, -1)
            return row[pos].strip() if 0 <= pos < len(row) else ""

        full_name = _get_col("full_name")
        matric_number = _get_col("matric_number").upper()
        gts_number = _get_col("gts_number").upper()
        phone_number = _get_col("phone_number")

        # Skip blank or repeated header rows
        if not full_name and not matric_number:
            continue
        if full_name.lower() in ("full name", "name", "student name") and matric_number.lower().startswith("matric"):
            continue

        students.append(
            {
                "full_name": full_name,
                "matric_number": matric_number,
                "gts_number": gts_number,
                "phone_number": phone_number,
            }
        )

    if not students:
        return {
            "ok": False,
            "error": "No student rows found. Make sure your file has Full Name, Matric Number, GTS Number, and Phone Number columns.",
        }

    return {"ok": True, "students": students}


def generate_sample_xlsx_bytes():
    """Generate a valid minimal Excel (.xlsx) template in memory with sample student rows."""
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        "</Types>"
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        "</Relationships>"
    )
    wb_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
        "</Relationships>"
    )
    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        '<sheets><sheet name="Students" sheetId="1" r:id="rId1"/></sheets>'
        "</workbook>"
    )
    sample_rows = [
        ["Full Name", "Matric Number", "GTS Number", "Phone Number"],
        ["Adebayo Oluwaseun", "CSC/2023/001", "GTS-2026-1001", "08031234567"],
        ["Chidinma Okafor", "CSC/2023/002", "GTS-2026-1002", "08059876543"],
        ["Ibrahim Musa", "CSC/2023/003", "GTS-2026-1003", "08023456789"],
    ]
    row_xml_parts = []
    for r_idx, row in enumerate(sample_rows, start=1):
        cells_xml = []
        for c_idx, val in enumerate(row):
            col_letter = chr(ord("A") + c_idx)
            escaped = (
                str(val)
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
            )
            cells_xml.append(
                f'<c r="{col_letter}{r_idx}" t="inlineStr"><is><t>{escaped}</t></is></c>'
            )
        row_xml_parts.append(f'<row r="{r_idx}">{"".join(cells_xml)}</row>')

    sheet1 = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f'<sheetData>{"".join(row_xml_parts)}</sheetData>'
        "</worksheet>"
    )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", rels)
        zf.writestr("xl/workbook.xml", workbook)
        zf.writestr("xl/_rels/workbook.xml.rels", wb_rels)
        zf.writestr("xl/worksheets/sheet1.xml", sheet1)
    return buf.getvalue()


# ==========================================
# ASSIGNMENTS & PROJECTS SCORES (STEP 4)
# ==========================================
def list_all_assessments():
    """Fetch all documents from the 'class_assessments' collection in Firestore."""
    url = f"{FIRESTORE_BASE_URL}/class_assessments?pageSize=300"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            return []
        docs = resp.json().get("documents", [])
        assessments = [_from_firestore_doc(d) for d in docs if d]
        result = [a for a in assessments if a is not None]
        result.sort(key=lambda x: x.get("created_at", ""))
        return result
    except Exception:
        return []


def get_assessments_by_class(class_id):
    if not class_id:
        return []
    items = [a for a in list_all_assessments() if a.get("class_id") == class_id]
    for a in items:
        if not isinstance(a.get("scores"), dict):
            a["scores"] = {}
    return items


def get_assessment_by_id(assessment_id):
    if not assessment_id:
        return None
    url = f"{FIRESTORE_BASE_URL}/class_assessments/{assessment_id}"
    try:
        resp = requests.get(url, timeout=8)
        if resp.status_code == 200:
            doc = _from_firestore_doc(resp.json())
            if doc and not isinstance(doc.get("scores"), dict):
                doc["scores"] = {}
            return doc
        return None
    except Exception:
        return None


def create_class_assessment(
    class_id,
    lecturer_id,
    title,
    category="Assignment",
    max_score=10,
    date_given="",
    description="",
):
    """Create a new Assignment or Project score column for a class."""
    title_clean = (title or "").strip()
    category_clean = (category or "Assignment").strip().title()
    if category_clean not in ("Assignment", "Project", "Practical", "Test"):
        category_clean = "Assignment"

    if not title_clean:
        return {"ok": False, "error": "Please enter a title for the Assignment or Project."}

    try:
        max_val = float(max_score)
        if max_val <= 0:
            max_val = 10.0
        if max_val.is_integer():
            max_val = int(max_val)
    except (ValueError, TypeError):
        max_val = 10

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    if not date_given:
        date_given = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    assess_doc = {
        "class_id": class_id,
        "lecturer_id": lecturer_id,
        "title": title_clean,
        "category": category_clean,
        "max_score": max_val,
        "date_given": date_given.strip(),
        "description": (description or "").strip(),
        "scores": {},
        "created_at": now_iso,
    }

    fields = {k: _to_firestore_value(v) for k, v in assess_doc.items()}
    url = f"{FIRESTORE_BASE_URL}/class_assessments"

    try:
        resp = requests.post(url, json={"fields": fields}, timeout=10)
        if resp.status_code in (200, 201):
            return {"ok": True, "assessment": _from_firestore_doc(resp.json())}
        return {"ok": False, "error": f"Firestore error ({resp.status_code}): {resp.text}"}
    except Exception as exc:
        return {"ok": False, "error": f"Failed to create assessment: {exc}"}


def save_assessment_scores(assessment_id, scores_updates):
    """
    Merge and save student scores on an Assignment or Project in a single Firestore PATCH call.
    scores_updates: dict of {student_id: score_value_or_None}
    """
    assessment = get_assessment_by_id(assessment_id)
    if not assessment:
        return {"ok": False, "error": "Assessment not found."}

    max_score = float(assessment.get("max_score") or 100)
    current_scores = dict(assessment.get("scores") or {})
    updated_count = 0

    for student_id, raw_val in scores_updates.items():
        if not student_id:
            continue
        val_str = str(raw_val).strip() if raw_val is not None else ""
        if val_str == "":
            # If cleared, remove score entry if present
            if student_id in current_scores:
                del current_scores[student_id]
            continue

        try:
            num_val = float(val_str)
            if num_val < 0:
                num_val = 0.0
            if num_val > max_score:
                num_val = max_score
            if num_val.is_integer():
                num_val = int(num_val)
            else:
                num_val = round(num_val, 2)
            current_scores[student_id] = num_val
            updated_count += 1
        except (ValueError, TypeError):
            continue

    url = f"{FIRESTORE_BASE_URL}/class_assessments/{assessment_id}?updateMask.fieldPaths=scores"
    fields = {"scores": _to_firestore_value(current_scores)}

    try:
        resp = requests.patch(url, json={"fields": fields}, timeout=12)
        if resp.status_code == 200:
            return {
                "ok": True,
                "assessment": _from_firestore_doc(resp.json()),
                "updated_count": updated_count,
            }
        return {"ok": False, "error": f"Failed to save scores ({resp.status_code}): {resp.text}"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def delete_class_assessment(assessment_id):
    if not assessment_id:
        return {"ok": False, "error": "Missing assessment ID."}
    url = f"{FIRESTORE_BASE_URL}/class_assessments/{assessment_id}"
    try:
        resp = requests.delete(url, timeout=8)
        if resp.status_code in (200, 204):
            return {"ok": True}
        return {"ok": False, "error": f"Failed to delete assessment ({resp.status_code})."}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def enrich_students_with_assessments(students, assessments):
    """
    Attach each student's Assignment and Project scores and totals directly onto their student dict:
    - st['assessment_scores']: {assessment_id: score}
    - st['assignment_total']: sum of scores for 'Assignment' category
    - st['project_total']: sum of scores for 'Project' category
    - st['overall_total']: sum of all assessment scores
    """
    assignment_max_total = 0
    project_max_total = 0
    overall_max_total = 0

    for a in assessments:
        m = float(a.get("max_score") or 0)
        m_fmt = int(m) if m.is_integer() else round(m, 2)
        overall_max_total += m_fmt
        if (a.get("category") or "Assignment").lower() == "project":
            project_max_total += m_fmt
        else:
            assignment_max_total += m_fmt

    for st in students:
        sid = st.get("id", "")
        st_scores = {}
        assign_sum = 0.0
        proj_sum = 0.0
        total_sum = 0.0

        for a in assessments:
            aid = a.get("id", "")
            scores_map = a.get("scores") or {}
            if sid in scores_map and scores_map[sid] is not None:
                val = float(scores_map[sid])
                val_fmt = int(val) if val.is_integer() else round(val, 2)
                st_scores[aid] = val_fmt
                total_sum += val
                if (a.get("category") or "Assignment").lower() == "project":
                    proj_sum += val
                else:
                    assign_sum += val
            else:
                st_scores[aid] = None

        st["assessment_scores"] = st_scores
        st["assignment_total"] = int(assign_sum) if assign_sum.is_integer() else round(assign_sum, 2)
        st["project_total"] = int(proj_sum) if proj_sum.is_integer() else round(proj_sum, 2)
        st["overall_total"] = int(total_sum) if total_sum.is_integer() else round(total_sum, 2)

    return {
        "assignment_max_total": assignment_max_total,
        "project_max_total": project_max_total,
        "overall_max_total": overall_max_total,
    }


def parse_scores_spreadsheet(filename, file_bytes, class_students):
    """
    Parse an uploaded Excel (.xlsx) or CSV (.csv) file containing student identifiers
    (GTS Number, Matric Number, Phone Number, or Full Name) and their Score.
    Returns {student_id: score_str}.
    """
    fname_lower = (filename or "").lower()
    if not file_bytes:
        return {"ok": False, "error": "Uploaded file is empty."}

    try:
        if fname_lower.endswith(".xlsx") or file_bytes[:2] == b"PK":
            raw_rows = _parse_xlsx_bytes(file_bytes)
        elif fname_lower.endswith(".csv") or fname_lower.endswith(".txt"):
            raw_rows = _parse_csv_bytes(file_bytes)
        else:
            return {"ok": False, "error": "Unsupported file format. Please upload .xlsx or .csv."}
    except Exception as exc:
        return {"ok": False, "error": f"Failed to read spreadsheet: {exc}"}

    if not raw_rows:
        return {"ok": False, "error": "No rows found in uploaded file."}

    # Build lookup maps for class_students
    by_gts = {}
    by_matric = {}
    by_phone = {}
    by_name = {}

    for st in class_students:
        sid = st.get("id")
        if not sid:
            continue
        gts_clean = re.sub(r"[^A-Z0-9]+", "", (st.get("gts_number") or "").upper())
        gts_digits = re.sub(r"[^0-9]+", "", (st.get("gts_number") or ""))
        if gts_clean:
            by_gts[gts_clean] = sid
        if gts_digits and len(gts_digits) >= 5:
            by_gts[gts_digits] = sid

        if _is_valid_id(st.get("matric_number")):
            mat_clean = re.sub(r"[^A-Z0-9]+", "", (st.get("matric_number") or "").upper())
            if mat_clean:
                by_matric[mat_clean] = sid

        ph_digits = re.sub(r"[^0-9]+", "", (st.get("phone_number") or ""))
        if len(ph_digits) >= 7:
            by_phone[ph_digits[-9:]] = sid

        nm_clean = re.sub(r"\s+", " ", (st.get("full_name") or "").strip().upper())
        if nm_clean:
            by_name[nm_clean] = sid

    # Detect Score column vs Identifier columns
    first_row_norm = [re.sub(r"[^a-z0-9]+", " ", c.lower()).strip() for c in raw_rows[0]]
    score_col = -1
    start_idx = 0

    for idx, cell in enumerate(first_row_norm):
        if any(w in cell for w in ("score", "mark", "grade", "point", "assignment", "project", "total")):
            score_col = idx
            start_idx = 1
            break

    if score_col == -1:
        if any(w in " ".join(first_row_norm) for w in ("name", "matric", "gts", "phone")):
            start_idx = 1
        score_col = len(raw_rows[0]) - 1

    matched_scores = {}
    for row in raw_rows[start_idx:]:
        if not row or score_col >= len(row):
            continue
        score_str = str(row[score_col]).strip()
        if not score_str:
            continue
        try:
            float(score_str)
        except ValueError:
            continue

        # Try matching student using other columns in the row
        matched_sid = None
        for c_idx, cell_val in enumerate(row):
            if c_idx == score_col or not cell_val:
                continue
            c_upper = str(cell_val).strip().upper()
            c_alnum = re.sub(r"[^A-Z0-9]+", "", c_upper)
            c_digits = re.sub(r"[^0-9]+", "", c_upper)

            if c_alnum in by_matric:
                matched_sid = by_matric[c_alnum]
                break
            if c_alnum in by_gts:
                matched_sid = by_gts[c_alnum]
                break
            if c_digits and len(c_digits) >= 5 and c_digits in by_gts:
                matched_sid = by_gts[c_digits]
                break
            if c_digits and len(c_digits) >= 7 and c_digits[-9:] in by_phone:
                matched_sid = by_phone[c_digits[-9:]]
                break
            nm = re.sub(r"\s+", " ", c_upper)
            if nm in by_name:
                matched_sid = by_name[nm]
                break

        if matched_sid:
            matched_scores[matched_sid] = score_str

    if not matched_scores:
        return {
            "ok": False,
            "error": "Could not match any students from the uploaded file. Include GTS Number, Matric Number, or Full Name and a Score column.",
        }

    return {"ok": True, "scores": matched_scores}




