#!/bin/bash

rm -rf Migrations

dotnet ef migrations add Application -c ApplicationDbContext -o Migrations/ApplicatonDb
dotnet ef migrations script -c ApplicationDbContext -o Migrations/ApplicationDb.sql