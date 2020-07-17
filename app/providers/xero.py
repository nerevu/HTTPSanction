# -*- coding: utf-8 -*-
"""
    app.providers.xero
    ~~~~~~~~~~~~~~~~~~

    Provides Xero API related functions
"""
from functools import partial
from datetime import date
from decimal import Decimal

import pygogo as gogo

from app.utils import fetch_choice
from app.helpers import get_collection, get_provider
from app.mappings import USERS, NAMES, POSITIONS, gen_task_mapping
from app.routes.webhook import Webhook
from app.routes.auth import Resource, process_result

logger = gogo.Gogo(__name__, monolog=True).logger

TWOPLACES = Decimal(10) ** -2
PREFIX = __name__.split(".")[-1]


def events_processor(result, fields, **kwargs):
    result = process_result(result, fields, **kwargs)
    return ({**item, "day": item["dateUtc"].split("T")[0]} for item in result)


def get_position_user_ids(xero_task_name):
    position_name = xero_task_name.split("(")[1][:-1]

    try:
        user_ids = POSITIONS[position_name]
    except KeyError:
        logger.debug(f"Position map doesn't contain position '{position_name}'!")
        user_ids = []

    return user_ids


def get_user_name(user_id, prefix=None):
    Users = get_collection(prefix, "users")
    users = Users(dry_run=True, rid=user_id)
    user = users.extract_model(update_cache=True, strict=True)
    return user[users.name_field]


def parse_date(date_str):
    year, month, day = map(int, date_str.split("T")[0].split("-"))
    return date(year, month, day).strftime("%b %-d, %Y")


###########################################################################
# Resources
###########################################################################
class Status(Resource):
    def __init__(self, *args, **kwargs):
        super().__init__(PREFIX, "status", *args, **kwargs)


class Projects(Resource):
    def __init__(self, *args, **kwargs):
        fields = ["projectId", "name", "status"]
        kwargs.update({"fields": fields, "id_field": "projectId", "subkey": "items"})
        super().__init__(PREFIX, "projects", *args, **kwargs)

    def get_post_data(self, project, project_name, rid, **kwargs):
        client = project["client"]
        kwargs.update({"dry_run": self.dry_run, "dest_prefix": self.prefix})
        xero_contact = Contacts.from_source(client, **kwargs)

        if xero_contact:
            project_data = {
                "contactId": xero_contact["ContactID"],
                "name": project_name,
            }

            if project.get("budget"):
                project_data["estimateAmount"] = project["budget"]
        else:
            project_data = {}

        return project_data


class Users(Resource):
    def __init__(self, *args, **kwargs):
        fields = ["userId", "name"]
        kwargs.update({"fields": fields, "id_field": "userId", "subkey": "items"})
        super().__init__(PREFIX, "projectsusers", *args, **kwargs)

    def id_func(self, user, user_name, rid, prefix=None):
        matching = list(enumerate(x["name"] for x in self))
        none_of_prev = [(len(matching), "None of the previous users")]
        choices = matching + none_of_prev
        pos = fetch_choice(choices) if choices else None

        try:
            item = self[pos]
        except (IndexError, TypeError):
            xero_user_id = None
        else:
            xero_user_id = item["userId"]

        return xero_user_id


class Contacts(Resource):
    def __init__(self, *args, **kwargs):
        kwargs.update(
            {
                "fields": ["ContactID", "Name", "FirstName", "LastName"],
                "id_field": "ContactID",
                "subkey": "Contacts",
                "domain": "api",
            }
        )
        super().__init__(PREFIX, "Contacts", *args, **kwargs)


class Invoices(Resource):
    def __init__(self, *args, **kwargs):
        kwargs.update(
            {
                "fields": [],
                "id_field": "InvoiceID",
                "subkey": "Invoices",
                "domain": "api",
                "name_field": "InvoiceNumber",
            }
        )

        super().__init__(PREFIX, "Invoices", *args, **kwargs)


class OnlineInvoices(Resource):
    def __init__(self, *args, **kwargs):
        kwargs.update(
            {
                "id_field": "OnlineInvoiceUrl",
                "subkey": "OnlineInvoices",
                "domain": "api",
                "subresource": "OnlineInvoice",
            }
        )

        super().__init__(PREFIX, "Invoices", *args, **kwargs)


class EmailTemplate(Resource):
    def __init__(self, *args, **kwargs):
        kwargs["get_response"] = self.get_response
        super().__init__(PREFIX, "Invoices", *args, **kwargs)
        self.recipient_name = kwargs.get("recipient_name")
        self.recipient_email = kwargs.get("recipient_email")

    def get_line_item(self, LineAmount=0, DiscountAmount=0, **kwargs):
        item_price = Decimal(LineAmount) + Decimal(DiscountAmount)
        line_item = {
            "description": kwargs["Description"],
            "item_price": str(Decimal(item_price).quantize(TWOPLACES)),
        }
        return line_item

    def get_response(self):
        invoices = Invoices(rid=self.id)
        invoice = invoices.extract_model()
        invoice_num = invoice["InvoiceNumber"]
        items = [self.get_line_item(**item) for item in invoice["LineItems"]]
        customer = invoice["Contact"]
        charge_date = parse_date(invoice["DueDateString"])
        invoice_date = parse_date(invoice["DateString"])
        subtotal = invoice["AmountDue"] + invoice["TotalDiscount"]

        try:
            address = next(x for x in customer["Addresses"] if x.get("AddressLine1"))
        except StopIteration:
            address = {}

        online_invoices = OnlineInvoices(rid=self.id)
        online_invoice = online_invoices.extract_model()

        model = {
            "contact_name": customer["FirstName"],
            "reference": invoice["Reference"],
            "charge": str(Decimal(invoice["AmountDue"]).quantize(TWOPLACES)),
            "currency": invoice["CurrencyCode"],
            "charge_date": charge_date,
            "link": online_invoice[online_invoices.id_field],
            "customer_name": customer["Name"],
            "invoice_num": invoice_num,
            "invoice_date": invoice_date,
            "items": items,
            "subtotal": str(Decimal(subtotal).quantize(TWOPLACES)),
            "discount": str(Decimal(invoice["TotalDiscount"]).quantize(TWOPLACES)),
            "address": address,
        }
        def_name = "{FirstName} {LastName}".format(**customer)

        result = {
            "model": model,
            "name": def_name if self.recipient_name is None else self.recipient_name,
            "email": self.recipient_email or customer["EmailAddress"],
            "filename": "Nerevu Invoice {invoice_num}.pdf".format(**model),
            "pdf": invoices.extract_model(headers={"Accept": "application/pdf"}),
            "metadata": {"client-id": customer["ContactID"]},
        }

        return {"result": result}


class Inventory(Resource):
    def __init__(self, *args, **kwargs):
        kwargs.update(
            {
                "fields": ["ItemID", "Name", "Code", "Description", "SalesDetails"],
                "id_field": "ItemID",
                "subkey": "Items",
                "domain": "api",
                "name_field": "Name",
            }
        )

        super().__init__(PREFIX, "Items", *args, **kwargs)

    def get_matching_xero_postions(self, user_id, task_name, user_name=None):
        trunc_name = task_name.split(" ")[0]
        names = NAMES[trunc_name]
        logger.debug(f"Loading {self} choices for {user_name}…")
        matching_tasks = [
            r for r in self if any(n in r[self.name_field] for n in names)
        ]
        return [
            t
            for t in matching_tasks
            if user_id in get_position_user_ids(t[self.name_field])
        ]


class ProjectTasks(Resource):
    def __init__(self, *args, **kwargs):
        # TODO: filter by active xero tasks
        kwargs.update(
            {
                "fields": ["taskId", "name", "status", "rate.value", "projectId"],
                "id_field": "taskId",
                "subkey": "items",
                "map_factory": None,
                "entry_factory": None,
                "rid_hook": self.hook,
                "subresource": "tasks",
            }
        )

        super().__init__(PREFIX, "projects", *args, **kwargs)

    def get_task_entry(self, rid, source_rid, prefix=None):
        (project_id, user_id, label_id) = source_rid
        entry = {}
        entry[prefix.lower()] = {
            "task": label_id,
            "project": project_id,
            "users": USERS[user_id],
        }
        entry[self.lowered] = {"task": rid, "project": self.rid}
        return entry

    def hook(self):
        if self.rid:
            xero_users = Users(dry_run=self.dry_run)
            xero_projects = Projects(dry_run=True)

            self.entry_factory = self.get_task_entry
            self.map_factory = partial(
                gen_task_mapping,
                user_mappings=xero_users.mappings,
                project_mappings=xero_projects.mappings,
            )

    def get_matching_xero_postions(self, user_id, task_name, user_name=None):
        trunc_name = task_name.split(" ")[0]
        names = NAMES[trunc_name]
        logger.debug(f"Loading {self} choices for {user_name}…")
        matching_tasks = [
            r for r in self if any(n in r[self.name_field] for n in names)
        ]
        return [
            t
            for t in matching_tasks
            if user_id in get_position_user_ids(t[self.name_field])
        ]

    def get_post_data(self, task, task_name, rid, prefix=None):
        (project_id, user_id, label_id) = rid
        args = (user_id, task_name, get_user_name(user_id, prefix=prefix))
        matching_task_positions = self.get_matching_xero_postions(*args)
        task_position_names = {t["name"] for t in matching_task_positions}

        xero_inventory = Inventory(dry_run=self.dry_run)
        matching_inventory_positions = xero_inventory.get_matching_xero_postions(*args)
        matching_positions = [
            m
            for m in matching_inventory_positions
            if m["Name"] not in task_position_names
        ]

        matching = list(
            enumerate(
                f"{m['Name']} - {m['SalesDetails']['UnitPrice']}"
                for m in matching_positions
            )
        )

        none_of_prev = [(len(matching), "None of the previous tasks")]
        choices = matching + none_of_prev
        pos = fetch_choice(choices) if choices else None

        try:
            item = matching_positions[pos]
        except (IndexError, TypeError):
            item = {}

        try:
            rate = item["SalesDetails"]["UnitPrice"]
        except KeyError:
            task_data = {}
        else:
            task_data = {
                "name": item["Name"],
                "rate": {"currency": "USD", "value": rate},
                "chargeType": "TIME" if rate else "NON_CHARGEABLE",
            }

        return task_data

    def id_func(self, task, task_name, rid, prefix=None):
        (project_id, user_id, label_id) = rid
        args = (user_id, task_name, get_user_name(user_id, prefix=prefix))
        matching_task_positions = self.get_matching_xero_postions(*args)
        matching = list(enumerate(m["name"] for m in matching_task_positions))
        none_of_prev = [(len(matching), "None of the previous tasks")]
        choices = matching + none_of_prev
        pos = fetch_choice(choices) if choices else None

        try:
            item = matching_task_positions[pos]
        except (IndexError, TypeError):
            xero_task_id = None
        else:
            xero_task_id = item["taskId"]

        return xero_task_id


class ProjectTime(Resource):
    def __init__(self, source_prefix="timely", *args, **kwargs):
        self.source_prefix = source_prefix
        self.event_pos = int(kwargs.pop("event_pos", 0))
        self.event_id = kwargs.pop("event_id", None)
        self.source_event = None
        self.eof = False
        self.source_project_id = kwargs.pop("source_project_id", None)
        kwargs.update(
            {
                "id_field": "timeEntryId",
                "subkey": "items",
                "subresource": "time",
                "processor": events_processor,
            }
        )

        super().__init__(PREFIX, "projects", *args, **kwargs)

    def set_post_data(self):
        prefix = self.source_prefix
        provider = get_provider(prefix)
        assert provider, (f"Provider {prefix.lower()} doesn't exist!", 404)
        self.source_project_id = self.values.get(
            "sourceProjectId", self.source_project_id
        )
        source_projects = provider.Projects(
            rid=self.source_project_id, use_default=True, dry_run=self.dry_run
        )
        ekwargs = {"update_cache": True, "strict": True}
        source_project = source_projects.extract_model(**ekwargs)
        self.source_project_id = source_project[source_projects.id_field]

        self.event_pos = int(self.values.get("eventPos", self.event_pos))
        source_project_events = provider.ProjectTime(
            use_default=True,
            rid=self.source_project_id,
            pos=self.event_pos,
            dry_run=self.dry_run,
        )
        self.source_event = source_project_events.extract_model(update_cache=True)
        self.eof = source_project_events.eof
        assert self.source_event, (f"{source_project_events} doesn't exist!", 404)
        self.event_id = self.source_event[source_project_events.id_field]
        added = self.results.get(self.event_id, {}).get("added")
        assert not added, (f"{source_project_events} already added!", 409)

        label_id = self.source_event.get("label_id")
        assert label_id, (f"{source_project_events} missing label!", 500)
        self.source_event["label_id"] = label_id

        unbilled = not self.source_event["billed"]
        assert unbilled, (f"{source_project_events} is already billed!", 409)

        self.day = self.source_event["day"]
        assert self.day, (f"{source_project_events} has no day!", 500)

        self.duration = self.source_event["duration.total_minutes"]
        assert self.duration, (f"{source_project_events} has no duration!", 500)
        skwargs = {
            "dry_run": self.dry_run,
            "dest_prefix": self.prefix,
            "source_prefix": prefix,
        }
        xero_project = Projects.from_source(source_project, **skwargs)
        self.rid = xero_project["projectId"]

        source_user_id = self.source_event["user.id"]
        source_users = provider.Users(dry_run=self.dry_run, rid=source_user_id)
        source_user = source_users.extract_model(**ekwargs)
        source_user_name = source_user["name"]
        xero_user = Users.from_source(source_user, **skwargs)
        assert xero_user, (f"User {source_user_name} doesn't exist in Xero!", 404)

        source_tasks = provider.Tasks(dry_run=self.dry_run)
        source_task = source_tasks.extract_model(label_id, **ekwargs)
        source_rid = (self.source_project_id, source_user_id, label_id)
        xero_task = ProjectTasks.from_source(
            source_task, rid=self.rid, source_rid=source_rid, **skwargs,
        )
        assert xero_task, (f"Task {source_rid} doesn't exist in Xero!", 404)

        self.xero_user_id = xero_user["userId"]
        self.xero_task_id = xero_task["taskId"]

        xero_tunc_user_id = self.xero_user_id.split("-")[0]
        xero_trunc_task_id = self.xero_task_id.split("-")[0]

        key = (self.day, self.duration, self.xero_user_id, self.xero_task_id)
        truncated_key = (self.day, self.duration, xero_tunc_user_id, xero_trunc_task_id)

        fields = ["day", "duration", "userId", "taskId"]
        event_keys = {tuple(event[f] for f in fields) for event in self}
        error = (f"Xero time entry {truncated_key} already exists!", 409)
        assert key not in event_keys, error

    def get_post_data(self, *args, **kwargs):
        # url = 'http://localhost:5000/v1/xero-time'
        # r = requests.post(url, data={"sourceProjectId": 2389295, "dryRun": True})
        try:
            self.set_post_data()
        except AssertionError as err:
            self.error_msg, self.status_code = err.args[0]
            data = {}
        else:
            date_utc = f"{self.day}T12:00:00Z"
            note = self.source_event["note"]
            description = f"{note[:64]}…" if len(note) > 64 else note

            data = {
                "userId": self.xero_user_id,
                "taskId": self.xero_task_id,
                "dateUtc": date_utc,
                "duration": self.duration,
                "description": description,
            }

        return data


class Hooks(Webhook):
    def __init__(self, *args, **kwargs):
        super().__init__(PREFIX, *args, **kwargs)

    def process_value(self, value):
        result = {}

        for event in value:
            key = (event["eventType"].lower(), event["eventCategory"].lower())
            method = self.methods.get(key)

            if method:
                response = method(event["ResourceId"])
                result[event["eventId"]] = response.get("response")

        return result
