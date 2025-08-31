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

// A simple class to statically define permission verbs
class Permission {
  static CREATE = "CREATE"
  static READ = "READ"
  static UPDATE = "UPDATE"
  static DELETE = "DELETE"
  static SHARE = "SHARE"
  static ALL = "ALL"
}

// Role is the association class joining User, target and permissions
class Role {
  constructor(roleId, roleName, roleDescription, target, permissions=[]){
    if(!roleId) throw new Error("roleId must be provided");
    if(!roleName) throw new Error("roleName must be provided");
    if(!target) throw new Error("target must be provided");
    if(!(target instanceof Target)) throw new Error("target must be an instance of Target");
    this.roleId = roleId;
    this.roleName = roleName;
    this.roleDescription = roleDescription;
    this.target = target; // instance of Target class
    this.permissions = permissions; // array of permission strings
  }
  // getter methods
  get roleId() { return this.roleId; }
  get roleName() { return this.roleName; }
  get roleDescription() { return this.roleDescription; }
  get target() { return this.target; }
  get permissions() { return this.permissions; }

  // add permission to role. permissions must be one of the defined static verbs in Permission class
  addPermission(permission) {
    if(!permission) throw new Error("permission is null or undefined");
    if(permission !== Permission.CREATE && permission !== Permission.READ && 
      permission !== Permission.UPDATE && permission !== Permission.DELETE && 
      permission !== Permission.SHARE && permission !== Permission.ALL) {
        throw new Error("Invalid permission: " + permission +". Must be one of CREATE, READ, UPDATE, DELETE, SHARE, ALL");
    }
    if(this.permissions.find(p => p.verb === permission.verb && p.targetType === permission.targetType))
      throw new Error("permission already exists in role");
    this.permissions.push(permission);
  }
  removePermission(permission) {
    this.permissions = this.permissions.filter(p => {p.verb !== permission.verb || p.targetType !== permission.targetType});
  }

  authorize(permission, target) { 
    // input validation
    if(!target) {
      throw new Error("target must be provided");
    } else if(!(target instanceof Target)){
        throw new Error("target must be an instance of Target");
    } 
    if(!verb) {
      throw new Error("verb must be provided");
    } else if(verb!=Permission.verb_CREATE && verb!=Permission.verb_READ && 
      verb!=Permission.verb_UPDATE && verb!=Permission.verb_DELETE && 
      verb!=Permission.verb_SHARE && verb!=Permission.verb_ALL) {
        throw new Error("Invalid verb: " + verb +". Must be one of CREATE, READ, UPDATE, DELETE, SHARE, ALL");
    }
    // start authorization logic, set targetMatch to false initially
    let targetMatch = false;
    // check if the target matches the role's target exactly
    if(!targetMatch) targetMatch = (this.target.targetSignature === target.targetSignature);
    // if not, check if the role's target is a parent of the target
    if(!targetMatch) {
      let children = this.target.loadChildren();
      if(children.find(c => c.targetSignature === target.targetSignature)) {
        targetMatch = true;
      } 
    }
    // return true if target matches and verb is allowed in permissions
    return targetMatch && this.permissions.find(p => p === permission);
  }
}
  

// Target represents the node on which actions can be performed. The actions are defined by verbs in Permission class
// Target can be at different levels of hierarchy: tenant, workspace, job, discussion
// Target is defined by a targetSignature in the format tenant/workspace/job/discussion
// where workspace, job, discussion can be wildcard (*) to represent all objects at that level
// e.g. tenant/*/*/* represents all objects under the tenant
// e.g. tenant/workspace/*/* represents all objects under the workspace
// e.g. tenant/workspace/job/* represents all discussions under the job
// e.g. tenant/workspace/job/discussion represents the specific discussion
class Target {
  constructor(tenant, workspace, job, discussion) {
    if(!tenant) throw new Error("Tenant must be provided");
    this.tenant = tenant; // required
    this.workspace = workspace; // optional
    this.job = job; // optional
    this.discussion = discussion; // optional
    // set targetSignature based on provided params in the format tenant/workspace/job/discussion
    this.targetSignature = tenant + "/" + (workspace ? workspace : "*") + "/" + (job ? job : "*") + "/" + (discussion ? discussion : "*");
  }
  get tenant() { return this.tenant; }
  get workspace() { return this.workspace; }
  get job() { return this.job; }
  get discussion() { return this.discussion; }
  get targetSignature() { return this.targetSignature; }
  
  loadChildren() {
    /**
     * return an array of Target instances representing child objects of the node
     * load all child objects from DB or API, given the tenant, workspace, job, disscussion values
     * if only tenant is provided, load all workspaces, jobs and discussions under the tenant
     * if tenant and workspace is provided, load all jobs and discussions under the workspace
     * if tenant, workspace and object is provided, load discussions under the object
     * if tenant, workspace, object and discussion is provided, return empty array as there are no children
     **/
    let childObjects = []; // TODO: implement
    /**
     * mockup of expected output:
     */
    childObjects.push(new Target(this.tenant, "marketing", "*", "*"));
    childObjects.push(new Target(this.tenant, "marketing", "job789", "*")); 
    childObjects.push(new Target(this.tenant, "marketing", "job789", "interview1"));
    childObjects.push(new Target(this.tenant, "marketing", "job789", "interview2"));
    childObjects.push(new Target(this.tenant, "marketing", "job789", "hrfeedback"));   
    childObjects.push(new Target(this.tenant, "engineering", "*", "*"));
    childObjects.push(new Target(this.tenant, "engineering", "job123", "*"));
    childObjects.push(new Target(this.tenant, "engineering", "job123", "discussion456"));
    return childObjects;

  }
}
class RBACUtil {
 static authorizeUser(user, permission, target) {
    // input validation
    if(!user) {
      throw new Error("user must be provided");
    } else if(!(user instanceof User)){
        throw new Error("user must be an instance of User");
    } 
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
    // start authorization logic, iterate through user's roles and check if any role authorizes the action on the target
    for(let role of user.roles) {
      if(role.authorize(permission, target)) {
        return true; // authorized
      }
    }
    return false; // not authorized
  }
}

// User class represents a user in the system with a unique userId and an array of roles. 
// This shoud be populated from DB or API and cached in session
class User {
  constructor(userId, userName, roles=[]) {
    if(!userId) throw new Error("userId must be provided");
    this.userId = userId;
    this.userName = userName;
    this.roles = roles; // array of Role instances
  }
  get userId() { return this.userId; }
  get userName() { return this.userName; }
  get roles() { return this.roles; }
}

export { Permission, Role, Target, User, RBACUtil };
