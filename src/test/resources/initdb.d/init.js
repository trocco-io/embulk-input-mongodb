db.getSiblingDB("$external").runCommand(
  {
    createUser: "CN=localhost",
    roles: [
      { role: "readWrite", db: "mydb" },
      { role: "readWrite", db: "embulk_test" },
      { role: "userAdminAnyDatabase", db: "admin" }
    ],
    writeConcern: { w: "majority" , wtimeout: 5000 }
  }
);

db.getSiblingDB("mydb").runCommand(
  {
    createUser: 'mongo_user',
    pwd:'dbpass',
    roles:[
      { role:'readWrite', db:'mydb' }
    ]
  }
)

db.getSiblingDB("embulk_test").runCommand(
  {
    createUser: 'mongo_user',
    pwd:'dbpass',
    roles:[
      { role:'readWrite', db:'embulk_test' }
    ]
  }
);

db.getSiblingDB("embulk_test").products.insert({category : 'A' , name : "camera case" , stock : 5});
