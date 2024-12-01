db.getSiblingDB("$external").runCommand(
  {
    createUser: "CN=localhost",
    roles: [
         { role: "readWrite", db: "mydb" },
         { role: "userAdminAnyDatabase", db: "admin" }
    ],
    writeConcern: { w: "majority" , wtimeout: 5000 }
  }
);

db.getSiblingDB("mydb").runCommand(
  {
    createUser:'mongo_user',
    pwd:'dbpass',
    roles:[
      {role:'readWrite',db:'mydb'}
    ]
  }
);
