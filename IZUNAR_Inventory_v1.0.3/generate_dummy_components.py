import random
from faker import Faker
from app import app, db, Component, Tag

fake = Faker('tr_TR')

TYPES = ["Elektronik", "Mekanik", "Kablo", "Sensör", "Motor", "Batarya", "Devre", "Konnektör", "Modül", "Diğer"]
CATEGORIES = ["demirbas", "sarf"]

def random_tags(existing_tags, k=2):
    return random.sample(existing_tags, k=min(k, len(existing_tags)))

def main():
    with app.app_context():
        # Önce bazı tagler ekle (varsa atla)
        tag_names = ["Arduino", "Raspberry", "Lityum", "Step Motor", "LED", "Direnç", "Kondansatör", "Buton", "Kablo", "Pil"]
        for name in tag_names:
            tag = Tag.query.filter_by(name=name).first()
            if not tag:
                tag = Tag(name=name)
                db.session.add(tag)
        db.session.commit()
        tags = Tag.query.all()

        for i in range(1000):
            name = fake.word().capitalize() + f" {fake.random_int(100, 999)}_{i+1}"
            category = random.choice(CATEGORIES)
            type_ = random.choice(TYPES)
            location = f"Raf-{random.randint(1,20)}"
            description = fake.sentence(nb_words=8)
            quantity = random.randint(1, 200)
            image_url = "https://via.placeholder.com/300x200?text=Ürün"
            part_number = f"PN{random.randint(1000,9999)}"
            code = f"{type_[:2].upper()}-{name[:3].upper()}-{i+1}"

            component = Component(
                name=name,
                category=category,
                type=type_,
                location=location,
                description=description,
                quantity=quantity,
                image_url=image_url,
                part_number=part_number,
                code=code
            )
            component.tags = random_tags(tags, k=random.randint(1, 3))
            db.session.add(component)

            if (i+1) % 100 == 0:
                print(f"{i+1} ürün eklendi...")
                db.session.commit()
        db.session.commit()
        print("Toplam 1000 ürün başarıyla eklendi.")

if __name__ == "__main__":
    main()
