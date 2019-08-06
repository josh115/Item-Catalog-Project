#!/usr/bin/env python2.7

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Item, Base, Category, User

# Connect to database
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

# Add test user
User1 = User(name="Test", email="test@gmail.com")
session.add(User1)
session.commit()

# Add soft drinks category
category1 = Category(user_id=1, name="Soft Drinks")
session.add(category1)
session.commit()

# Add chocolate category
category2 = Category(user_id=1, name="Chocolate")
session.add(category2)
session.commit()

# Add hot drinks category
category3 = Category(user_id=1, name="Hot Drinks")
session.add(category3)
session.commit()

# Add item coca cola
item1 = Item(name="Coca Cola", user_id=1,
             description=("Coca-Cola Classic is the world's "
                          "favourite soft drink and has been enjoyed "
                          "since 1886."),
             category=category1)
session.add(item1)
session.commit()

# Add item snickers
item2 = Item(name="Snickers", user_id=1,
             description=("Milk chocolate with soft nougat and caramel "
                          "centre with fresh roasted peanuts."),
             category=category2)
session.add(item2)
session.commit()

# Add item coffee
item3 = Item(name="Coffee", user_id=1,
             description="Soluble coffee with finely ground roasted coffee.",
             category=category3)
session.add(item3)
session.commit()

# Add item sprite
item4 = Item(name="Sprite", user_id=1,
             description=("Sparkling Lemon-Lime Flavour Soft Drink with "
                          "Sugar and Sweetener."),
             category=category1)
session.add(item4)
session.commit()

# Add item fanta
item5 = Item(name="Fanta", user_id=1,
             description=("Sparkling Orange Fruit Drink with Sugar "
                          "and Sweeteners."),
             category=category1)
session.add(item5)
session.commit()

print ("Database Updated")
