from marshmallow import Schema, fields, validate

# Registration Schema
class RegisterSchema(Schema):
    fname = fields.Str(required=True, validate=validate.Length(min=1))
    lname = fields.Str(required=True, validate=validate.Length(min=1))
    email = fields.Email(required=True)
    password = fields.Str(required=True, validate=validate.Length(min=6))

# Login Schema
class LoginSchema(Schema):
    email = fields.Email(required=True)
    password = fields.Str(required=True, validate=validate.Length(min=6))

# Add other schemas here as needed
