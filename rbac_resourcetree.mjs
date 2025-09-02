/*
MIT License

Copyright (c) 2025 Pranav Ganguly

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

// A simple class to statically define permission permissions
class Permission {
  static CREATE = "CREATE"
  static READ = "READ"
  static UPDATE = "UPDATE"
  static DELETE = "DELETE"
  static SHARE = "SHARE"
  static ALL = "ALL"
}

// Target represents the node on which actions can be performed. The actions are defined by permissions in Permission class
// Target is represented by a nested scope uri based on the different levels of hierarchy
// e.g. target://tenant/workspace/job/discussion represents a specific discussion
// e.g. target://tenant represents all objects under the tenant
// e.g. target://tenant/workspace represents all objects under the workspace
// e.g. target://tenant/workspace/job represents the job and all discussions under the job
// Any heirarchy can work with any level of depth
// e.g. target://animalia/phylum/class/order/family/genus/species or target://company/department/team/member

class Target {
  constructor(...argStrings){ 
    // can be called with at least one or any number of Strings which will 
    // be compiled into a uri like target://arg1/arg2/arg3/arg4...
    if(argStrings.length===0) throw new Error("Needs at least one argument");
    if(argStrings.filter(arg => typeof arg !== 'string').length>0) throw new Error("All arguments must be strings");
    this.level = Array.from(argStrings);
    this.uri = "target://" + this.level.join("/");
  }
}

// User class represents a user in the system with a unique userId and an array of roles. 
// This shoud be populated from DB or API and cached in session
class User {
  constructor(userId, userName, roles) {
    if(!userId) throw new Error("userId must be provided");
    if(!roles) throw new Error("roles must be provided");
    if(!Array.isArray(roles)) throw new Error("roles must be an array");
    if(roles.filter(r => !(r instanceof Role)).length>0) throw new Error("all roles must be instances of Role class");
    this.roles = roles; // array of Role instances
    this.userId = userId;
    this.userName = userName;
  }
}

// Role is the association class joining User, target and permissions
class Role {
  constructor(roleId, roleName, roleDescription, target, permissions=[]){
    if(!roleId) throw new Error("roleId must be provided");
    if(!roleName) throw new Error("roleName must be provided");
    if(!target){ throw new Error("target must be provided");
    } else if( typeof target === 'string') {
        this.targets = [new Target(...target.split('/'))]; // convert string to Target instance
    } else if( target instanceof Target ) {
        this.targets = [target]; // already a Target instance
    } else if( Array.isArray(target) && target.every(t => typeof t === 'string') ) {
      this.targets = target.map(t => new Target(...t.split('/'))); // array of strings to array of Target instances
    } else if( Array.isArray(target) && target.every(t => t instanceof Target) ) {
      this.targets = target; // already an array of Target instances
    } else {
      throw new Error("Invalid target. Must be a string, Target instance or array of strings/Target instances");
    }
    this.roleId = roleId;
    this.roleName = roleName;
    this.roleDescription = roleDescription;
    this.target = target; // instance of Target class
    this.permissions = permissions; // array of permission strings
  }
  // add permission to role. permissions must be one of the defined static permissions in Permission class
  addPermission(permission) {
    if(!permission) throw new Error("permission is null or undefined");
    if(permission !== Permission.CREATE && permission !== Permission.READ && 
      permission !== Permission.UPDATE && permission !== Permission.DELETE && 
      permission !== Permission.SHARE && permission !== Permission.ALL) {
        throw new Error("Invalid permission: " + permission +". Must be one of CREATE, READ, UPDATE, DELETE, SHARE, ALL");
    }
    if(this.permissions.find(p => p.permission === permission.permission && p.targetType === permission.targetType))
      throw new Error("permission already exists in role");
    this.permissions.push(permission);
  }
  removePermission(permission) {
    this.permissions = this.permissions.filter(p => {p.permission !== permission.permission || p.targetType !== permission.targetType});
  }

  authorize(permission, target) { 
    // input validation
    if(!target) {
      throw new Error("target must be provided");
    } else if(!(target instanceof Target)){
        throw new Error("target must be an instance of Target");
    } 
    if(!permission) {
      throw new Error("permission must be provided");
    } else if(permission!=Permission.CREATE && permission!=Permission.READ && 
      permission!=Permission.UPDATE && permission!=Permission.DELETE && 
      permission!=Permission.SHARE && permission!=Permission.ALL) {
        throw new Error("Invalid permission: " + permission +". Must be one of CREATE, READ, UPDATE, DELETE, SHARE, ALL");
    }
    // return true if target matches and permission is allowed in permissions
    return this.targets.find(rt => target.uri.indexOf(rt.uri)===0) && this.permissions.find(p => p === permission || p === Permission.ALL);
  }
}
/**
 * Sample role
 * let role1 = new Role("admin", "Client Admin", "Manages the whole org", new Target("ACME"), [Permission.ALL]);
 */


// RBACUtil is a simple wrapper over the static utility method for RBAC authorization
class RBACUtil {

  // authorizeUser checks if the user has the required permission on the target
  // returns true if authorized, false otherwise
  // throws error if input is invalid

  static authorizeUser(user, permission, target) {
    // input validation
    if(!user || !(user instanceof User))
      throw new Error("user must be provided and must be an instance of User");
    if(!target || !(target instanceof Target))
      throw new Error("target must be provided and must be an instance of Target");
    if(!permission || (permission!=Permission.CREATE && permission!=Permission.READ && 
      permission!=Permission.UPDATE && permission!=Permission.DELETE && 
      permission!=Permission.SHARE && permission!=Permission.ALL)) {
        throw new Error("Invalid permission: " + permission +". Must be one of CREATE, READ, UPDATE, DELETE, SHARE, ALL");
    }
    // start authorization logic, iterate through user's roles and check if any role authorizes the action on the target
    for(let role of user.roles) {
      if(role.authorize(permission, target)) {
        return true; // authorized
      }
    }
    return false; // not authorized
  }
}

class RBACDemo {
  static run() {
    // create some sample users, roles and targets
    
    let ingenAdmin = new Role(
      "IngenAdmin", 
      "IngenAdmin", 
      "Admin role with all permissions for InGen tenant", 
      new Target("InGen"), 
      [Permission.ALL]
    );
    let ingenEnggHM = new Role(
      "IngenEnggHM", 
      "IngenEngineeringHiringManager", 
      "Hiring Manager role with read, write and delete permissions for InGen Engineering workspace", 
      new Target("InGen", "Engineering", "job789"), 
      [Permission.READ, Permission.CREATE, Permission.UPDATE, Permission.DELETE]
    );
    let ingenEnggTAM = new Role(
      "IngenEnggTAM", 
      "IngenEngineeringTalentAquisitionManager", 
      "Talent Aquisition Manager role with read and write permissions for InGen Engineering workspace", 
      [new Target("InGen", "Engineering"), new Target("InGen", "HR")], 
      [Permission.ALL]
    );
    let ingenInterviewer1 = new Role(
      "IngenInterviewer", 
      "IngenInterviewer", 
      "Interviewer role with read and write permissions for InGen Engineering workspace", 
      new Target("InGen", "Engineering", "job789", "Interview1"), 
      [Permission.READ, Permission.UPDATE]
    );
    let ingenInterviewer2 = new Role(
      "IngenInterviewer", 
      "IngenInterviewer", 
      "Interviewer role with read and write permissions for InGen Engineering workspace", 
      new Target("InGen", "Engineering", "job789", "Interview2"), 
      [Permission.READ, Permission.UPDATE]
    );

    let anita = new User("anita", "Anita", [ingenEnggHM]);
    let bala = new User("bala", "Bala", [ingenAdmin]);
    let charu = new User("charu", "Charu", [ingenEnggTAM]);
    let deepak = new User("deepak", "Deepak", [ingenInterviewer1]);
    let esha = new User("esha", "Esha", [ingenInterviewer2, ingenEnggTAM]);

    //check some authorizations
    console.log("Is Anita allowed to READ InGen/Engineering/job789/Interview1? " + 
      RBACUtil.authorizeUser(anita, Permission.READ, new Target("InGen", "Engineering", "job789", "Interview1"))); // true
    console.log("Is Anita allowed to DELETE InGen/Engineering/job789/Interview1? " + 
      RBACUtil.authorizeUser(anita, Permission.DELETE, new Target("InGen", "Engineering", "job789", "Interview1"))); // true
    console.log("Is Anita allowed to CREATE InGen/Engineering/job789/Interview2? " + 
      RBACUtil.authorizeUser(anita, Permission.CREATE, new Target("InGen", "Engineering", "job789", "Interview2"))); // false
    console.log("Is Bala allowed to DELETE InGen/HR/job555/discussion999? " + 
      RBACUtil.authorizeUser(bala, Permission.DELETE, new Target("InGen", "HR", "job555", "discussion999"))); // true
    console.log("Is Deepak allowed to UPDATE InGen/HR/job555/discussion999? " + 
      RBACUtil.authorizeUser(deepak, Permission.UPDATE, new Target("InGen", "HR", "job555", "discussion999")));
      
  }
}


export { Permission, Role, Target, User, RBACUtil, RBACDemo };
