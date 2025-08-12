from marshmallow import Schema, fields, validate, pre_load

class MetadataSchema(Schema):
    name = fields.Str(required=True)
    labels = fields.Dict(keys=fields.Str(), values=fields.Str(), load_default=dict)
    annotations = fields.Dict(keys=fields.Str(), values=fields.Str(), load_default=dict)

class SpecSchema(Schema):
    description = fields.Str(required=False, allow_none=True)
    owner = fields.Str(required=False, allow_none=True)
    display_name = fields.Str(required=False, allow_none=True, data_key="display-name")

class ProjectSchema(Schema):
    apiVersion = fields.Str(required=True, validate=validate.Equal("mygroup.example.com/v1"))
    kind = fields.Str(required=True, validate=validate.Equal("Project"))
    metadata = fields.Nested(MetadataSchema, required=True)
    spec = fields.Nested(SpecSchema, required=False)

    @pre_load
    def fix_display_name(self, data, **kwargs):
        # Allow accepting both 'display-name' and 'display_name' keys
        if 'spec' in data and 'display_name' in data['spec']:
            data['spec']['display-name'] = data['spec'].pop('display_name')
        return data
