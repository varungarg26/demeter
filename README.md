# demeter

<h3>What is Demeter</h3>

Demeter is a Web Application accessed through logging into the website or registering as a new user. Once you are logged in, you will see your dashboard, which will allow you to create a new group if you are not already in one or join an existing group.

The meat of this project exists in the groups! Once you are in a group, you can then post items from your grocery list onto one master grocery list for all members of the group to view. Each item has two required fields for "item name" and "quantity" and an optional field for "comments". The list will grow as other members continue to add their items to the list as well. This is the list that the 'grocery picker' will refer to when at the store.

In the group dashboard, there will be a button named "volunteer for pickup", which can be clicked by any member of the group. Once this button is clicked, the group members will be notified that a member of the group is going to the nearest grocery store to purchase groceries.

On the 'grocery picker's' end, as they are purchasing groceries, they can remove purchased items from the list. Once they have purchased all the groceries, they can then deliver everyone's respective groceries to their doorstep! After the groceries are dropped off, the group will be disbanded and a new one can be created for the next grocery adventure!

<h3>How it was built</h3>

When we set out to make Demeter, we determined 3 key principals to lead us through the frustrating bugs, the sleepless nights and the constant design debates. Simplicity, Efficiency and Scalability.

We wanted Demeter to be simple to design, upgrade and debug. This meant leveraging the magic of Python and Flask to design a REST API for the needed backend endpoints. Furthermore, for a prototype application, the use of SQLite3 encouraged rapid development, testing and debugging.

For the front end, we used jinja2 templates as they integrate perfectly with the Flask backend and base HTML/CSS/JS. This was to limit the system overhead needed to run the application otherwise required by more bulky frameworks like React and Angular. The integration also allowed for concurrent development of both the front-end and back-end.
