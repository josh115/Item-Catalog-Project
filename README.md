## Description

This is an application that uses the flask framework to display a catalog of items from a database which uses CRUD operations using sqlalchemy to create, read, update and delete items from the database. This will be managed by using user registration and authentication system by using a third party OAuth authentication so that only the person the created an item can edit or delete it.

## Instructions

1. Download and install the following:

    [VirtualBox 6.0.8](https://www.virtualbox.org/wiki/Downloads)
	
    [Vagrant 2.2.5](https://www.vagrantup.com/downloads.html)

2. Once you have installed the above download or use git clone to install [fullstack-nanodegree-vm](https://github.com/udacity/fullstack-nanodegree-vm) into your chosen directory, this will run your virtual machine with the correct modules required.

3. Navigate to the fullstack-nanodegree-vm directory then run ```vagrant up``` in the terminal to start the virtual machine. Once it has started use ```vagrant ssh``` to log into the virtual machine. 

4. Once you have connected to the virtual machine use ```cd /vagrant``` to navigate to your shared directory.

5. Create a new directory called catalog by using ```mkdir catalog```.

6. Download the files in this repository or fork the repository and use git clone and place files inside the catalog directory you just created.

7. Navigate to the catalog directory and setup the database by using ```python database_setup.py```.

8. Populate the database with some test data by using ```python addtodatabase.py```

9. Now the database has been created and some test data has been added run the application by using ```python application.py```

10. Now open ```http://localhost:5000/``` inside your browser (Developed using chrome so other browsers may not support the css)