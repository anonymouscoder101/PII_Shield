"""Seeded invented records, never sampled from personal records or credentials."""

import random
from importlib.metadata import version

from faker import Faker

GENERATOR_VERSION = "1"


class _Message:
    def __init__(self, message_index=0):
        self.text = ""
        self.labels = []
        self.message_index = message_index

    def add(self, text, entity_type=None):
        start = len(self.text)
        self.text += text
        if entity_type is not None:
            self.labels.append(
                {
                    "message_index": self.message_index,
                    "start": start,
                    "end": len(self.text),
                    "entity_type": entity_type,
                    "value": text,
                }
            )
        return self


def generate_dataset(*, seed=1729, count=150):
    """Return a JSON-compatible manifest with exact half-open Python offsets.

    Six templates rotate without filtering for detector success: email, ticket,
    note, difficult contact formats, repeated conversation, and clean negatives.
    Names use locally seeded Faker; dates use seeded calendar fields. Email/IP/phone use
    example or documentation ranges, keys include SYNTHETIC_ONLY, cards use
    published test values, and SSNs have invalid area 900 (validator challenge).
    """
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise ValueError("count must be a positive integer")
    rng = random.Random(seed)
    fake = Faker("en_US")
    fake.seed_instance(seed)
    cases = []
    for index in range(count):
        template = index % 6
        name = fake.first_name() + " Example"
        email = f"synthetic.{seed}.{index}@example.test"
        phone = f"+1 202-555-{rng.randint(100, 199):04d}"
        employee = f"EMP-{index + 1000:06d}"
        action = rng.choice(
            [
                "Review the technical draft.",
                "Confirm the delivery schedule.",
                "Prepare a brief status update.",
                "Resolve the configuration issue.",
            ]
        )
        msg = _Message().add("🛡️ e\u0301 — Synthetic record. ")
        msg.add(
            (
                "Email",
                "Support ticket",
                "Note",
                "Contact note",
                "Conversation note",
                "Clean negative",
            )[template]
            + ".\n"
        )
        msg.add("Task: Extract the Action and Contact lines verbatim.\n")
        msg.add(f"Action: {action}\nContact: ")
        if template in (0, 2, 4):
            msg.add(name, "PERSON")
            if template in (0, 4):
                msg.add(" | ").add(email, "EMAIL_ADDRESS")
        elif template == 3:
            msg.add(rng.choice(["李 Example", "José Example", "Zoë Example"]), "PERSON")
            msg.add(" | ").add(
                f"synthetic.{index} [at] example [dot] test", "EMAIL_ADDRESS"
            )
        else:
            msg.add("technical team")
        msg.add("\n")
        if template == 0:
            msg.add("Phone: ").add(phone, "PHONE_NUMBER")
            msg.add("\nMeet in ").add(
                rng.choice(["London", "Paris", "Berlin"]), "LOCATION"
            )
            msg.add(" at ").add(f"{index + 100} Example Street", "ADDRESS").add(".\n")
        elif template == 1:
            msg.add('api_key="').add(f"SYNTHETIC_ONLY_API_{seed}_{index}", "API_KEY")
            msg.add('"\npassword="').add(f"SYNTHETIC_ONLY_SECRET_{index}", "SECRET")
            msg.add('"\nEmployee: ').add(employee, "EMPLOYEE_ID")
            msg.add("\nIP: ").add(f"192.0.2.{index % 254 + 1}", "IP_ADDRESS").add("\n")
        elif template == 2:
            msg.add("DOB: ").add(
                f"{rng.randint(1940, 2005):04d}-{rng.randint(1, 12):02d}-"
                f"{rng.randint(1, 28):02d}",
                "DATE_OF_BIRTH",
            )
            msg.add("\nSynthetic SSN: ").add(
                f"900-{rng.randint(10, 99)}-{rng.randint(1000, 9999)}", "US_SSN"
            )
            msg.add("\nTest card: ").add("4111 1111 1111 1111", "CREDIT_CARD").add("\n")
        elif template == 3:
            msg.add("Reference: ").add(phone, "PHONE_NUMBER")
            msg.add("\nHome: ").add(f"Flat {index + 1}, Example House", "ADDRESS")
            msg.add("\nDate of birth: ").add("3rd May 1988", "DATE_OF_BIRTH").add("\n")
        elif template == 4:
            msg.add("Again: ").add(name, "PERSON").add(" uses ")
            msg.add(email, "EMAIL_ADDRESS").add("\n")
        else:
            msg.add("Version v2.7.4; build 12345; ratio 01/02; ticket EMP-X.\n")
        messages = [{"role": "user", "content": msg.text}]
        labels = list(msg.labels)
        if template == 4:
            repeated = _Message(1).add("Previous synthetic reply: ")
            repeated.add(name, "PERSON").add(" uses ").add(email, "EMAIL_ADDRESS")
            messages.append({"role": "assistant", "content": repeated.text})
            labels.extend(repeated.labels)
        cases.append(
            {
                "id": f"synthetic-{seed}-{index:04d}",
                "synthetic": True,
                "template": (
                    "email",
                    "ticket",
                    "note",
                    "difficult",
                    "repeated",
                    "negative",
                )[template],
                "request": {
                    "model": "synthetic-model",
                    "messages": messages,
                    "stream": False,
                },
                "entities": labels,
            }
        )
    return {
        "schema_version": 1,
        "generator_version": GENERATOR_VERSION,
        "seed": seed,
        "faker_version": version("Faker"),
        "locale": "en_US",
        "offset_convention": "half-open Python Unicode string indices",
        "synthetic_only": True,
        "cases": cases,
    }
