class AccessControlMatrix:
    def __init__(self,subjects,objects):
        self.matrix = {}
        for subject in subjects:
            self.matrix[subject]={}
            for object in objects:
                self.matrix[subject][object] = set()

    def print_access(self):
        print("")
        print(self.matrix)

    def print_accessmatrix(self):
        for key1,value1 in self.matrix.items():
            for key2,value2 in value1.items():
                print("")
                print(f"{key1} can access {key2} with rights : {self.matrix[key1][key2]}")  

    def print_capability_list(self):
        non_empty_output = {}
        for key1, value1 in self.matrix.items():
            for key2, value2 in value1.items():
                rights = self.matrix[key1][key2]
                if rights:
                    if key1 not in non_empty_output:
                        non_empty_output[key1] = {}
                    if key2 not in non_empty_output[key1]:
                        non_empty_output[key1][key2] = set()
                    non_empty_output[key1][key2].update(rights)
        print(non_empty_output)
        print("")
        print("                                   Capability List :   ")
        print("")
        for key1, value1 in non_empty_output.items():
            for key2, value2 in value1.items():
                rights = non_empty_output[key1][key2]
                if rights:
                    print(f"{key1} can access {key2} with rights: {', '.join(rights)}")                          
    
    def print_acl_list(self):
        print()
        print("")
        print("                                    ACL list:")
        print("")
        output = {}
        for key1,value1 in self.matrix.items():
            for key2,value2 in value1.items():
                rights1 = self.matrix[key1][key2]
                rights2 = self.matrix.get(key2, {}).get(key1, set()) 
            
                if rights1:
                    if key2 not in output:
                        output[key2] = {}
                    if key1 not in output[key2]:
                        output[key2][key1] = set()
                    output[key2][key1].update(rights1)
                
                if rights2:
                    if key1 not in output:
                        output[key1] = {}
                    if key2 not in output[key1]:
                        output[key1][key2] = set()
                    output[key1][key2].update(rights2)   
        print("")
        print(output)
        print("")
        print("                                  ACL List :")
        print("")
        for key1, value1 in output.items():
            print(f"For \"{key1}\":")
            for key2, value2 in value1.items():
                rights = output[key1][key2]
                if rights:

                    print(f"{key2} : {rights}")   
    
    # create subject
    def create_subject(self,subject):
        if subject not in self.matrix:
            self.matrix[subject]={}
        for obj in self.matrix:
            self.matrix[subject][obj] = set()   # doubt 
    
    # create object 
    def create_object(self,obj):
        for subject in self.matrix:
            self.matrix[subject][obj]= set()

    #destroy subject
    def destroy_subject(self,subject):
        if subject in self.matrix:
            del self.matrix[subject]   

    # destroy object
    def destroy_object(self,obj):
        for subject in self.matrix:
            if obj in self.matrix[subject]:
                del self.matrix[subject][obj]

    #Add right
    def add_right(self,subject,object,rights):
        self.matrix[subject][object].update(rights)

    # Delete right
    def delete_right(self,subject,obj,delete_right):
        if subject in self.matrix and obj in self.matrix[subject]:
            self.matrix[subject][obj] -= set(delete_right)

    # Verify User
    def verify_user(self, verifier, verify_operation, user, user_identity):  
        if 'Read' in self.matrix[verifier][user] and 'Read' in self.matrix[verify_operation][user_identity]:
            if 'Call' in self.matrix[verifier][verify_operation]:
                if 'Read' in self.matrix[verify_operation][verifier]:
                    return True
        return False

    #Delete User
    def delete_user(self, deleter, delete_operation, user, user_identity):   
        if 'Delete' in self.matrix[deleter][user] and 'Delete' in self.matrix[delete_operation][user_identity]:
            if 'Read' in self.matrix[deleter][user]:
                    return True
        return False

    


subjects = ['User', 'Verifier', 'Verify Operation', 'Delete Operation']
objects = ['User', 'Verifier', 'Verify Operation', 'Delete Operation', 'User Identity']
acm = AccessControlMatrix(subjects,objects)

acm.add_right("User","User",["Read"])
acm.add_right("User","Verifier",["Read"])
acm.add_right("User","User Identity",["Read"])
acm.add_right("Verifier","User",["Read","Delete"])
acm.add_right("Verifier","Verifier",["Read"])
acm.add_right("Verifier","Verify Operation",["Call"])
acm.add_right("Verifier","Delete Operation",["Call"])
acm.add_right("Verifier","User Identity",["Read","Delete"])
acm.add_right("Verify Operation","User",["Read"])
acm.add_right("Verify Operation","Verifier",["Read"])
acm.add_right("Verify Operation","User Identity",["Read"])
acm.add_right("Delete Operation","User",["Read","Delete"])
acm.add_right("Delete Operation","Verifier",["Read"])
acm.add_right("Delete Operation","User Identity",["Read","Delete"])
print("")
print("                       Given  Access Matrix Input with  Subject ,Object  whose RightMode are Added in Program")
print("")
acm.print_access()

print("")
print("")

print("                                              Initial Capability List")
# Print capability List
print("")
acm.print_capability_list()
print("")
print("                                             Initial Access Control List")
# Print ACL list 
print("")
acm.print_acl_list()


print("")
print("")
# Create a new subject
acm.create_subject("New User")
acm.add_right("New User", "User", ["Read", "Delete"])
print("") 
print("                             New Subject added named as  New User along with its Acccess Rights")
print("")
acm.print_access()
print("")
print("")
acm.print_accessmatrix()
print("")
print("")
print("                     New Objects added named as New Object  New User Identity along with its Acccess Rights")
print("")
# Create a new object
acm.create_object("New Object")
acm.add_right("User", "New Object", ["Read"])
acm.add_right("Verifier", "New Object", ["Read"])
acm.create_object("New User Identity")
acm.add_right("New User", "New User Identity", ["Read"])

acm.print_access()
print("")
acm.print_accessmatrix()
print("")
print("")
print("")
# Destroy a subject and object
acm.destroy_subject("New User")

print("                             Destroy Subject  named as ==> [ New Usert ] is destroyed ")
print("")
acm.print_access()
print("")
acm.print_accessmatrix()
print("")
print("")
print("                            Destroy Object  named as ==> [ New User Object ] is destroyed ")
print("")
acm.destroy_object("New Object")
print("")
acm.print_access()
print("")
acm.print_accessmatrix()
print("")
print("")
print("                                                Verify User")

# Verify a user
verification_result = acm.verify_user("Verifier", "Verify Operation", "User", "User Identity")
print("User verification result:", verification_result)
print("")
acm.print_accessmatrix()
print("")
acm.print_access()
print("")
acm.print_accessmatrix()

print("")
print("")
print("                                               Delete User")

# Delete a user
deletion_result = acm.delete_user("Delete Operation", "Delete Operation", "User", "User Identity")
print("User deletion result:", deletion_result)
print("")
acm.print_access()
print("")
acm.print_accessmatrix()

print("")
print("                                          Final Capability List")
# Print capability List
print("")
acm.print_capability_list()
print("")
print("")
print("                                         Final Access Control List")
# Print ACL list 
print("")
acm.print_acl_list()
print("")