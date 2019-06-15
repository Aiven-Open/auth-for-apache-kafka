/** Copyright (c) 2019 Aiven, Helsinki, Finland. https://aiven.io/
 */

package io.aiven.kafka.auth;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AivenAclEntry {
  private String principalType;
  private Pattern principalRe;
  private Pattern operationRe;
  private Pattern resourceRe;
  private String resourceRePattern;

  /** Constructor. */
  public AivenAclEntry(String principalType, String principal, String operation,
          String resource, String resourcePattern) {
    this.principalType = principalType;
    this.principalRe = Pattern.compile(principal);
    this.operationRe = Pattern.compile(operation);
    if (resource != null) {
      this.resourceRe = Pattern.compile(resource);
    } else if (resourcePattern != null) {
      this.resourceRePattern = resourcePattern;
    }
  }

  /** Check if request matches this rule. */
  public Boolean check(String principalType, String principal, String operation, String resource) {
    if (this.principalType == null || this.principalType.equals(principalType)) {
      Matcher mp = this.principalRe.matcher(principal);
      Matcher mo = this.operationRe.matcher(operation);
      if (mp.find() && mo.find()) {
        Matcher mr = null;
        if (this.resourceRe != null) {
          mr = this.resourceRe.matcher(resource);
        } else if (this.resourceRePattern != null) {
          String resourceReStr = mp.replaceAll(this.resourceRePattern);
          Pattern resourceRe = Pattern.compile(resourceReStr);
          mr = resourceRe.matcher(resource);
        }
        if (mr != null && mr.find()) {
          return true;
        }
      }
    }
    return false;
  }
}
