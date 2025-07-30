import random
from app import app, db, generate_component_code
from models import Component, Tag

types = ["Rezistör", "Kondansatör", "Transistör", "Entegre", "Sensör", "Kablo", "Pil"]
names = [
    "10k Ohm", "100uF", "NPN", "LM358", "DHT11", "USB Kablosu", "AA Pil",
    "5V Regülatör", "Potansiyometre", "Breadboard", "LED Kırmızı", "Buton"
]
part_numbers = ["PN100", "PN200", "PN300", "PN400", "PN500", "PN600", "PN700"]

with app.app_context():
    for _ in range(1000):
        type_ = random.choice(types)
        name = random.choice(names)
        part_number = random.choice(part_numbers)

        code = generate_component_code(type_, name, part_number)

        comp = Component(
            name=name,
            type=type_,
            location="Depo A",
            description=f"Deneme açıklama {_}",
            quantity=random.randint(1, 50),
            image_url="https://via.placeholder.com/300x200?text=Ürün",
            part_number=part_number,
            code=code
        )
        db.session.add(comp)

    db.session.commit()
    print("1000 ürün başarıyla eklendi!")

