import os
from datetime import datetime, timedelta, date, time as time_t
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from bson import ObjectId
import bcrypt
import jwt

from database import db, create_document
from schemas import User as UserSchema, University as UniversitySchema, Property as PropertySchema, ViewingAvailability as ViewingAvailabilitySchema, Booking as BookingSchema

JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret")
JWT_ALG = "HS256"

app = FastAPI(title="UniNest Hub API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

auth_scheme = HTTPBearer()


# Helpers
class TokenData(BaseModel):
    id: str
    role: str
    fullName: str
    email: EmailStr


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False


def create_token(user: dict) -> str:
    payload = {
        "id": str(user["_id"]),
        "role": user["role"],
        "fullName": user["fullName"],
        "email": user["email"],
        "exp": datetime.utcnow() + timedelta(days=7),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(auth_scheme)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.user.find_one({"_id": ObjectId(payload["id"])})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def require_role(user, roles: List[str]):
    if user.get("role") not in roles:
        raise HTTPException(status_code=403, detail="Forbidden")


# Request/response models
class SignupPayload(BaseModel):
    fullName: str
    email: EmailStr
    mobileNumber: str
    password: str
    role: str = "student"
    companyName: Optional[str] = None


class LoginPayload(BaseModel):
    email: EmailStr
    password: str


class PropertyFilter(BaseModel):
    q: Optional[str] = None
    universityId: Optional[str] = None
    listingType: Optional[str] = None
    minBedrooms: Optional[int] = None
    minPrice: Optional[int] = None
    maxPrice: Optional[int] = None
    distanceText: Optional[str] = None  # matches against distanceToUniversityText


# Routes
@app.get("/")
def root():
    return {"app": "UniNest Hub API"}


@app.get("/test")
def test_database():
    resp = {"backend": "ok", "db": "not_connected"}
    try:
        collections = db.list_collection_names()
        resp["db"] = "ok"
        resp["collections"] = collections
    except Exception as e:
        resp["error"] = str(e)
    return resp


@app.post("/auth/signup")
def signup(payload: SignupPayload):
    if db.user.find_one({"email": payload.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    user = {
        "fullName": payload.fullName,
        "email": payload.email,
        "mobileNumber": payload.mobileNumber,
        "passwordHash": hash_password(payload.password),
        "role": payload.role,
        "companyName": payload.companyName,
        "createdAt": datetime.utcnow(),
        "updatedAt": datetime.utcnow(),
    }
    res = db.user.insert_one(user)
    user["_id"] = res.inserted_id
    token = create_token(user)
    return {"token": token, "user": {"id": str(user["_id"]), "fullName": user["fullName"], "email": user["email"], "role": user["role"]}}


@app.post("/auth/login")
def login(payload: LoginPayload):
    user = db.user.find_one({"email": payload.email})
    if not user or not verify_password(payload.password, user.get("passwordHash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(user)
    return {"token": token, "user": {"id": str(user["_id"]), "fullName": user["fullName"], "email": user["email"], "role": user["role"]}}


@app.get("/universities")
def list_universities():
    items = list(db.university.find({}))
    for i in items:
        i["id"] = str(i.pop("_id"))
    return items


@app.post("/seed")
def seed():
    # only seed if empty
    if db.university.count_documents({}) == 0:
        universities = [
            {"name": "North City University", "city": "North City", "campusName": "North Campus", "latitude": 53.8008, "longitude": -1.5491},
            {"name": "Riverdale University", "city": "Riverdale", "campusName": "River Campus", "latitude": 53.4808, "longitude": -2.2426},
            {"name": "Central Metropolitan University", "city": "Metro City", "campusName": "Central Campus", "latitude": 51.5074, "longitude": -0.1278},
        ]
        db.university.insert_many([{**u, "createdAt": datetime.utcnow(), "updatedAt": datetime.utcnow()} for u in universities])

    if db.user.count_documents({}) == 0:
        # create landlords
        landlords = [
            {"fullName": "Lena Properties", "email": "lena@props.com", "mobileNumber": "+44111222333", "passwordHash": hash_password("password123"), "role": "landlord", "companyName": "Lena Lettings"},
            {"fullName": "Metro Lettings", "email": "metro@lettings.com", "mobileNumber": "+44111222444", "passwordHash": hash_password("password123"), "role": "landlord", "companyName": "Metro Lettings"},
        ]
        students = [
            {"fullName": "Sam Student", "email": "sam@student.com", "mobileNumber": "+447700900111", "passwordHash": hash_password("password123"), "role": "student"},
            {"fullName": "Ava Student", "email": "ava@student.com", "mobileNumber": "+447700900222", "passwordHash": hash_password("password123"), "role": "student"},
        ]
        admin = {"fullName": "Site Admin", "email": "admin@uninesthub.com", "mobileNumber": "+447700900000", "passwordHash": hash_password("adminpass"), "role": "admin"}
        db.user.insert_many([{**u, "createdAt": datetime.utcnow(), "updatedAt": datetime.utcnow()} for u in landlords + students + [admin]])

    if db.property.count_documents({}) == 0:
        uni = db.university.find_one({"name": "North City University"})
        uni2 = db.university.find_one({"name": "Riverdale University"})
        l1 = db.user.find_one({"email": "lena@props.com"})
        l2 = db.user.find_one({"email": "metro@lettings.com"})
        props = [
            {
                "landlordId": str(l1["_id"]),
                "title": "5-bed student house on Victoria Road",
                "addressLine1": "12 Victoria Road",
                "city": "Jesmond",
                "postcode": "JES 1AB",
                "areaName": "Jesmond",
                "nearestUniversityId": str(uni["_id"]),
                "distanceToUniversityText": "8 mins walk",
                "listingType": "HOUSE",
                "houseBedroomsTotal": 5,
                "monthlyRent": 450,
                "deposit": 450,
                "tenancyLengthText": "12 months",
                "availableFrom": datetime.utcnow().date(),
                "billsIncluded": True,
                "furnished": True,
                "keyFeatures": ["Garden", "Dishwasher", "Two bathrooms"],
                "description": "Bright 5-bedroom student house with large kitchen, two bathrooms and garden.",
                "photos": [
                    "https://images.unsplash.com/photo-1560185127-6ed189bf02f4?auto=format&fit=crop&w=1200&q=60",
                    "https://images.unsplash.com/photo-1560448075-bb4caa6c8e28?auto=format&fit=crop&w=1200&q=60",
                ],
                "isActive": True,
                "createdAt": datetime.utcnow(),
                "updatedAt": datetime.utcnow(),
            },
            {
                "landlordId": str(l2["_id"]),
                "title": "En-suite room in 4-bed student house – Headingley",
                "addressLine1": "22 Oak Street",
                "city": "Leeds",
                "postcode": "LS6 2CD",
                "areaName": "Headingley",
                "nearestUniversityId": str(uni2["_id"]),
                "distanceToUniversityText": "12 mins walk",
                "listingType": "ROOM",
                "houseBedroomsTotal": 4,
                "roomLabel": "En-suite room",
                "roomType": "En-suite",
                "monthlyRent": 550,
                "deposit": 550,
                "tenancyLengthText": "12 months",
                "availableFrom": datetime.utcnow().date(),
                "billsIncluded": True,
                "furnished": True,
                "keyFeatures": ["En-suite", "Wi-Fi included", "Modern kitchen"],
                "description": "Cosy en-suite room in a friendly 4-bedroom student house.",
                "photos": [
                    "https://images.unsplash.com/photo-1505692794403-34d4982f88aa?auto=format&fit=crop&w=1200&q=60",
                ],
                "isActive": True,
                "createdAt": datetime.utcnow(),
                "updatedAt": datetime.utcnow(),
                "housematesInfo": "Mixed-gender house, tidy and friendly."
            },
        ]
        db.property.insert_many(props)

    # Create viewing slots for each property if none
    for prop in db.property.find({}):
        count_slots = db.viewingavailability.count_documents({"propertyId": str(prop["_id"])})
        if count_slots == 0:
            base = datetime.utcnow().date()
            slots = []
            for d in range(1, 8, 2):  # next two weeks alt days
                day = base + timedelta(days=d)
                for hour in [14, 16]:
                    slots.append({
                        "propertyId": str(prop["_id"]),
                        "date": day,
                        "startTime": time_t(hour, 0),
                        "endTime": time_t(hour + 1, 0),
                        "isBooked": False,
                        "createdAt": datetime.utcnow(),
                        "updatedAt": datetime.utcnow(),
                    })
            if slots:
                db.viewingavailability.insert_many(slots)

    return {"status": "seeded"}


@app.post("/properties/search")
def search_properties(filters: PropertyFilter = Body(default=PropertyFilter())):
    query = {"isActive": True}
    if filters.listingType:
        query["listingType"] = filters.listingType
    if filters.q:
        query["$or"] = [
            {"city": {"$regex": filters.q, "$options": "i"}},
            {"areaName": {"$regex": filters.q, "$options": "i"}},
            {"title": {"$regex": filters.q, "$options": "i"}},
        ]
    if filters.universityId:
        query["nearestUniversityId"] = filters.universityId
    if filters.minBedrooms:
        query["houseBedroomsTotal"] = {"$gte": filters.minBedrooms}
    if filters.minPrice or filters.maxPrice:
        pr = {}
        if filters.minPrice:
            pr["$gte"] = filters.minPrice
        if filters.maxPrice:
            pr["$lte"] = filters.maxPrice
        query["monthlyRent"] = pr
    if filters.distanceText:
        query["distanceToUniversityText"] = {"$regex": filters.distanceText, "$options": "i"}

    items = list(db.property.find(query))
    for i in items:
        i["id"] = str(i.pop("_id"))
    return items


@app.get("/properties/{prop_id}")
def get_property(prop_id: str):
    prop = db.property.find_one({"_id": ObjectId(prop_id)})
    if not prop:
        raise HTTPException(status_code=404, detail="Property not found")
    prop["id"] = str(prop.pop("_id"))
    # landlord basic
    ll = db.user.find_one({"_id": ObjectId(prop["landlordId"])}) if ObjectId.is_valid(prop.get("landlordId", "")) else None
    if ll:
        prop["landlord"] = {"id": str(ll["_id"]), "fullName": ll["fullName"], "email": ll["email"], "mobileNumber": ll["mobileNumber"]}
    # university
    uni = db.university.find_one({"_id": ObjectId(prop["nearestUniversityId"])}) if ObjectId.is_valid(prop.get("nearestUniversityId", "")) else None
    if uni:
        prop["university"] = {"id": str(uni["_id"]), "name": uni["name"], "city": uni["city"], "campusName": uni.get("campusName")}
    return prop


@app.get("/properties/{prop_id}/slots")
def get_slots(prop_id: str):
    slots = list(db.viewingavailability.find({"propertyId": prop_id, "isBooked": False}).sort([("date", 1), ("startTime", 1)]))
    for s in slots:
        s["id"] = str(s.pop("_id"))
    return slots


class BookingPayload(BaseModel):
    slotId: str
    fullName: str
    email: EmailStr
    mobileNumber: str
    notesFromStudent: Optional[str] = None


@app.post("/properties/{prop_id}/book")
def book_viewing(prop_id: str, payload: BookingPayload, user=Depends(get_current_user)):
    require_role(user, ["student"])  # only students
    # fetch slot atomically: mark booked if free
    slot = db.viewingavailability.find_one({"_id": ObjectId(payload.slotId), "propertyId": prop_id})
    if not slot:
        raise HTTPException(status_code=404, detail="Slot not found")
    if slot.get("isBooked"):
        raise HTTPException(status_code=409, detail="That slot has just been booked. Please select another.")

    # mark booked
    upd = db.viewingavailability.update_one({"_id": ObjectId(payload.slotId), "isBooked": False}, {"$set": {"isBooked": True, "updatedAt": datetime.utcnow()}})
    if upd.modified_count == 0:
        raise HTTPException(status_code=409, detail="That slot has just been booked. Please select another.")

    prop = db.property.find_one({"_id": ObjectId(prop_id)})
    if not prop:
        raise HTTPException(status_code=404, detail="Property not found")

    landlord = db.user.find_one({"_id": ObjectId(prop["landlordId"])}) if ObjectId.is_valid(prop.get("landlordId", "")) else None

    start_dt = datetime.combine(slot["date"], slot["startTime"])  # naive
    end_dt = datetime.combine(slot["date"], slot["endTime"])

    booking = {
        "propertyId": prop_id,
        "studentId": str(user["_id"]),
        "landlordId": str(landlord["_id"]) if landlord else None,
        "availabilitySlotId": payload.slotId,
        "startDateTime": start_dt,
        "endDateTime": end_dt,
        "status": "CONFIRMED",
        "notesFromStudent": payload.notesFromStudent,
        "createdAt": datetime.utcnow(),
        "updatedAt": datetime.utcnow(),
        "studentSnapshot": {"fullName": payload.fullName, "email": payload.email, "mobileNumber": payload.mobileNumber},
    }
    res = db.booking.insert_one(booking)

    # send notifications (log to collection for demo)
    notify(booking, prop, landlord, user)

    return {"ok": True, "bookingId": str(res.inserted_id)}


def notify(booking: dict, prop: dict, landlord: Optional[dict], student: dict):
    # Simple email log using a collection
    def fmt_time(dt: datetime):
        return dt.strftime("%A %d %B, %I:%M%p")

    student_email = {
        "to": student["email"],
        "subject": f"Your viewing is booked – {prop['title']}",
        "body": f"Hi {student['fullName']},\n\nYour viewing has been booked for the following property:\n\nProperty: {prop['title']}\nAddress: {prop['addressLine1']}, {prop.get('city','')} {prop.get('postcode','')}\nDate: {fmt_time(booking['startDateTime'])}\nTime: {booking['startDateTime'].strftime('%H:%M')}\n\nLandlord: {landlord['fullName'] if landlord else 'N/A'}\nContact: {landlord['email'] if landlord else ''} / {landlord['mobileNumber'] if landlord else ''}\n\nIf you need to change or cancel this viewing, you can do so from your 'My viewings' page.\n\nThanks,\nUniNest Hub"
    }
    db.emails.insert_one(student_email)

    if landlord:
        landlord_email = {
            "to": landlord["email"],
            "subject": f"New viewing booked – {prop['title']}",
            "body": f"Hi {landlord['fullName']},\n\nA student has booked a viewing for your property:\n\nProperty: {prop['title']}\nAddress: {prop['addressLine1']}, {prop.get('city','')} {prop.get('postcode','')}\nDate: {fmt_time(booking['startDateTime'])}\n\nStudent details:\nName: {student['fullName']}\nEmail: {student['email']}\nMobile: {student['mobileNumber']}\n\nYou can view all your upcoming bookings in your landlord dashboard.\n\nBest,\nUniNest Hub"
        }
        db.emails.insert_one(landlord_email)


@app.get("/student/bookings")
def my_bookings(user=Depends(get_current_user)):
    require_role(user, ["student"])
    items = list(db.booking.find({"studentId": str(user["_id"])}).sort("startDateTime", 1))
    for i in items:
        i["id"] = str(i.pop("_id"))
    return items


@app.post("/student/bookings/{booking_id}/cancel")
def cancel_booking(booking_id: str, user=Depends(get_current_user)):
    booking = db.booking.find_one({"_id": ObjectId(booking_id)})
    if not booking:
        raise HTTPException(status_code=404, detail="Booking not found")
    # Only student who booked or landlord can cancel
    if str(user["_id"]) not in [booking.get("studentId"), booking.get("landlordId")]:
        require_role(user, ["admin"])  # else must be admin

    if booking["status"] == "CANCELLED":
        return {"ok": True}

    db.booking.update_one({"_id": ObjectId(booking_id)}, {"$set": {"status": "CANCELLED", "updatedAt": datetime.utcnow()}})
    # free slot
    if booking.get("availabilitySlotId"):
        db.viewingavailability.update_one({"_id": ObjectId(booking["availabilitySlotId"])}, {"$set": {"isBooked": False, "updatedAt": datetime.utcnow()}})

    # send cancellation emails (log)
    prop = db.property.find_one({"_id": ObjectId(booking["propertyId"])})
    landlord = db.user.find_one({"_id": ObjectId(booking["landlordId"])}) if booking.get("landlordId") else None
    student = db.user.find_one({"_id": ObjectId(booking["studentId"])})
    send_cancellation_emails(booking, prop, landlord, student)

    return {"ok": True}


def send_cancellation_emails(booking: dict, prop: dict, landlord: Optional[dict], student: dict):
    def fmt_time(dt: datetime):
        return dt.strftime("%A %d %B, %I:%M%p")
    # student email
    db.emails.insert_one({
        "to": student["email"],
        "subject": f"Viewing cancelled – {prop['title']}",
        "body": f"Hi {student['fullName']},\n\nYour viewing for the following property has been cancelled:\n\nProperty: {prop['title']}\nOriginal date: {fmt_time(booking['startDateTime'])}\n\nIf this was a mistake, please visit the property page to book another viewing.\n\nThanks,\nUniNest Hub"
    })
    if landlord:
        db.emails.insert_one({
            "to": landlord["email"],
            "subject": f"Viewing cancelled – {prop['title']}",
            "body": f"Hi {landlord['fullName']},\n\nThe following viewing has been cancelled:\n\nProperty: {prop['title']}\nOriginal date: {fmt_time(booking['startDateTime'])}\n\nStudent details:\nName: {student['fullName']}\nEmail: {student['email']}\nMobile: {student['mobileNumber']}\n\nYou can see all current viewings in your landlord dashboard.\n\nBest,\nUniNest Hub"
        })


# Landlord endpoints (basic)
@app.get("/landlord/properties")
def landlord_properties(user=Depends(get_current_user)):
    require_role(user, ["landlord", "admin"])
    q = {} if user["role"] == "admin" else {"landlordId": str(user["_id"])}
    items = list(db.property.find(q))
    for i in items:
        i["id"] = str(i.pop("_id"))
    return items


class SlotInput(BaseModel):
    propertyId: str
    date: date
    startTime: str
    endTime: str


@app.post("/landlord/slots")
def create_slot(payload: SlotInput, user=Depends(get_current_user)):
    require_role(user, ["landlord"])
    prop = db.property.find_one({"_id": ObjectId(payload.propertyId)})
    if not prop or prop.get("landlordId") != str(user["_id"]):
        raise HTTPException(status_code=403, detail="Not your property")
    # insert slot
    st = datetime.strptime(payload.startTime, "%H:%M").time()
    et = datetime.strptime(payload.endTime, "%H:%M").time()
    slot = {
        "propertyId": payload.propertyId,
        "date": payload.date,
        "startTime": st,
        "endTime": et,
        "isBooked": False,
        "createdAt": datetime.utcnow(),
        "updatedAt": datetime.utcnow(),
    }
    res = db.viewingavailability.insert_one(slot)
    return {"id": str(res.inserted_id)}


@app.get("/admin/summary")
def admin_summary(user=Depends(get_current_user)):
    require_role(user, ["admin"])
    return {
        "students": db.user.count_documents({"role": "student"}),
        "landlords": db.user.count_documents({"role": "landlord"}),
        "properties": db.property.count_documents({}),
        "bookings": db.booking.count_documents({}),
    }


@app.get("/admin/users")
def admin_users(user=Depends(get_current_user)):
    require_role(user, ["admin"])
    items = list(db.user.find({}).sort("createdAt", -1))
    for i in items:
        i["id"] = str(i.pop("_id"))
        i.pop("passwordHash", None)
    return items


@app.get("/admin/bookings")
def admin_bookings(user=Depends(get_current_user)):
    require_role(user, ["admin"])
    items = list(db.booking.find({}).sort("createdAt", -1))
    for i in items:
        i["id"] = str(i.pop("_id"))
    return items
