"""
UniNest Hub Schemas (MongoDB via Pydantic)

Each class name will map to a collection using the lowercase class name.
Example: User -> "user"
"""
from __future__ import annotations
from typing import List, Optional, Literal
from pydantic import BaseModel, Field, EmailStr
from datetime import date, time, datetime

Role = Literal['student', 'landlord', 'admin']
ListingType = Literal['HOUSE', 'ROOM']
BookingStatus = Literal['PENDING', 'CONFIRMED', 'CANCELLED']

class User(BaseModel):
    fullName: str
    email: EmailStr
    mobileNumber: str
    passwordHash: str
    role: Role = 'student'
    createdAt: Optional[datetime] = None
    updatedAt: Optional[datetime] = None
    companyName: Optional[str] = None  # for landlords

class University(BaseModel):
    name: str
    city: str
    campusName: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    createdAt: Optional[datetime] = None
    updatedAt: Optional[datetime] = None

class Property(BaseModel):
    landlordId: str
    title: str
    addressLine1: str
    addressLine2: Optional[str] = None
    city: str
    postcode: str
    areaName: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    nearestUniversityId: str
    distanceToUniversityText: str
    listingType: ListingType
    houseBedroomsTotal: int
    roomLabel: Optional[str] = None
    roomType: Optional[str] = None
    monthlyRent: int
    deposit: int
    tenancyLengthText: str
    availableFrom: date
    billsIncluded: bool = False
    furnished: bool = True
    keyFeatures: List[str] = []
    description: str
    photos: List[str] = []
    isActive: bool = True
    createdAt: Optional[datetime] = None
    updatedAt: Optional[datetime] = None
    housematesInfo: Optional[str] = None

class ViewingAvailability(BaseModel):
    propertyId: str
    date: date
    startTime: time
    endTime: time
    isBooked: bool = False
    createdAt: Optional[datetime] = None
    updatedAt: Optional[datetime] = None

class Booking(BaseModel):
    propertyId: str
    studentId: str
    landlordId: str
    availabilitySlotId: Optional[str] = None
    startDateTime: datetime
    endDateTime: datetime
    status: BookingStatus = 'CONFIRMED'
    notesFromStudent: Optional[str] = None
    createdAt: Optional[datetime] = None
    updatedAt: Optional[datetime] = None
