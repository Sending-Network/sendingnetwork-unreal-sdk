/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#pragma once

#include "basejob.hpp"
#include "csapi/definitions/push_condition.hpp"
#include "csapi/definitions/push_rule.hpp"
#include "csapi/definitions/push_ruleset.hpp"

namespace Kazv::Api {

/*! \brief Retrieve all push rulesets.
 *
 * Retrieve all push rulesets for this user. Clients can "drill-down" on
 * the rulesets by suffixing a ``scope`` to this path e.g.
 * ``/pushrules/global/``. This will return a subset of this data under the
 * specified key e.g. the ``global`` key.
 */
class GetPushRulesJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// The global ruleset.
PushRuleset global() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

    /// Retrieve all push rulesets.
    explicit GetPushRulesJob(std::string serverUrl
    , std::string _accessToken
      
        
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody();

        

        

      GetPushRulesJob withData(JsonWrap j) &&;
      GetPushRulesJob withData(JsonWrap j) const &;
      };
      using GetPushRulesResponse = GetPushRulesJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Retrieve a push rule.
 *
 * Retrieve a single specified push rule.
 */
class GetPushRuleJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        

/// The specific push rule. This will also include keys specific to the
/// rule itself such as the rule's ``actions`` and ``conditions`` if set.
    
    PushRule data() const
    {
    return
      std::move(jsonBody().get()).get<PushRule>()
    ;
    }
        

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Retrieve a push rule.
 *
    * \param scope
    *   ``global`` to specify global rules.
    * 
    * \param kind
    *   The kind of rule
    * 
    * \param ruleId
    *   The identifier for the rule.
    */
    explicit GetPushRuleJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string scope , std::string kind , std::string ruleId 
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string scope, std::string kind, std::string ruleId);

        

        

      GetPushRuleJob withData(JsonWrap j) &&;
      GetPushRuleJob withData(JsonWrap j) const &;
      };
      using GetPushRuleResponse = GetPushRuleJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Delete a push rule.
 *
 * This endpoint removes the push rule defined in the path.
 */
class DeletePushRuleJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Delete a push rule.
 *
    * \param scope
    *   ``global`` to specify global rules.
    * 
    * \param kind
    *   The kind of rule
    * 
    * \param ruleId
    *   The identifier for the rule.
    */
    explicit DeletePushRuleJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string scope , std::string kind , std::string ruleId 
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string scope, std::string kind, std::string ruleId);

        

        

      DeletePushRuleJob withData(JsonWrap j) &&;
      DeletePushRuleJob withData(JsonWrap j) const &;
      };
      using DeletePushRuleResponse = DeletePushRuleJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Add or change a push rule.
 *
 * This endpoint allows the creation, modification and deletion of pushers
 * for this user ID. The behaviour of this endpoint varies depending on the
 * values in the JSON body.
 * 
 * When creating push rules, they MUST be enabled by default.
 */
class SetPushRuleJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Add or change a push rule.
 *
    * \param scope
    *   ``global`` to specify global rules.
    * 
    * \param kind
    *   The kind of rule
    * 
    * \param ruleId
    *   The identifier for the rule.
    * 
    * \param actions
    *   The action(s) to perform when the conditions for this rule are met.
    * 
    * \param before
    *   Use 'before' with a ``rule_id`` as its value to make the new rule the
    *   next-most important rule with respect to the given user defined rule.
    *   It is not possible to add a rule relative to a predefined server rule.
    * 
    * \param after
    *   This makes the new rule the next-less important rule relative to the
    *   given user defined rule. It is not possible to add a rule relative
    *   to a predefined server rule.
    * 
    * \param conditions
    *   The conditions that must hold true for an event in order for a
    *   rule to be applied to an event. A rule with no conditions
    *   always matches. Only applicable to ``underride`` and ``override`` rules.
    * 
    * \param pattern
    *   Only applicable to ``content`` rules. The glob-style pattern to match against.
    */
    explicit SetPushRuleJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string scope , std::string kind , std::string ruleId , immer::array<Variant> actions , std::optional<std::string> before  = std::nullopt, std::optional<std::string> after  = std::nullopt, immer::array<PushCondition> conditions  = {}, std::optional<std::string> pattern  = std::nullopt
        );
    

    static BaseJob::Query buildQuery(
    std::optional<std::string> before, std::optional<std::string> after);

      static BaseJob::Body buildBody(std::string scope, std::string kind, std::string ruleId, immer::array<Variant> actions, std::optional<std::string> before, std::optional<std::string> after, immer::array<PushCondition> conditions, std::optional<std::string> pattern);

        

        

      SetPushRuleJob withData(JsonWrap j) &&;
      SetPushRuleJob withData(JsonWrap j) const &;
      };
      using SetPushRuleResponse = SetPushRuleJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Get whether a push rule is enabled
 *
 * This endpoint gets whether the specified push rule is enabled.
 */
class IsPushRuleEnabledJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// Whether the push rule is enabled or not.
bool enabled() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Get whether a push rule is enabled
 *
    * \param scope
    *   Either ``global`` or ``device/<profile_tag>`` to specify global
    *   rules or device rules for the given ``profile_tag``.
    * 
    * \param kind
    *   The kind of rule
    * 
    * \param ruleId
    *   The identifier for the rule.
    */
    explicit IsPushRuleEnabledJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string scope , std::string kind , std::string ruleId 
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string scope, std::string kind, std::string ruleId);

        

        

      IsPushRuleEnabledJob withData(JsonWrap j) &&;
      IsPushRuleEnabledJob withData(JsonWrap j) const &;
      };
      using IsPushRuleEnabledResponse = IsPushRuleEnabledJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Enable or disable a push rule.
 *
 * This endpoint allows clients to enable or disable the specified push rule.
 */
class SetPushRuleEnabledJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Enable or disable a push rule.
 *
    * \param scope
    *   ``global`` to specify global rules.
    * 
    * \param kind
    *   The kind of rule
    * 
    * \param ruleId
    *   The identifier for the rule.
    * 
    * \param enabled
    *   Whether the push rule is enabled or not.
    */
    explicit SetPushRuleEnabledJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string scope , std::string kind , std::string ruleId , bool enabled 
        );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string scope, std::string kind, std::string ruleId, bool enabled);

        

        

      SetPushRuleEnabledJob withData(JsonWrap j) &&;
      SetPushRuleEnabledJob withData(JsonWrap j) const &;
      };
      using SetPushRuleEnabledResponse = SetPushRuleEnabledJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief The actions for a push rule
 *
 * This endpoint get the actions for the specified push rule.
 */
class GetPushRuleActionsJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

    // Result properties
        
        

    
/// The action(s) to perform for this rule.
immer::array<Variant> actions() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief The actions for a push rule
 *
    * \param scope
    *   Either ``global`` or ``device/<profile_tag>`` to specify global
    *   rules or device rules for the given ``profile_tag``.
    * 
    * \param kind
    *   The kind of rule
    * 
    * \param ruleId
    *   The identifier for the rule.
    */
    explicit GetPushRuleActionsJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string scope , std::string kind , std::string ruleId 
        );


    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string scope, std::string kind, std::string ruleId);

        

        

      GetPushRuleActionsJob withData(JsonWrap j) &&;
      GetPushRuleActionsJob withData(JsonWrap j) const &;
      };
      using GetPushRuleActionsResponse = GetPushRuleActionsJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

/*! \brief Set the actions for a push rule.
 *
 * This endpoint allows clients to change the actions of a push rule.
 * This can be used to change the actions of builtin rules.
 */
class SetPushRuleActionsJob : public BaseJob {
public:



class JobResponse : public Response
{

public:
  JobResponse(Response r);
  bool success() const;

};
          static constexpr auto needsAuth() {
          return true
            ;
              }


// Construction/destruction

  /*! \brief Set the actions for a push rule.
 *
    * \param scope
    *   ``global`` to specify global rules.
    * 
    * \param kind
    *   The kind of rule
    * 
    * \param ruleId
    *   The identifier for the rule.
    * 
    * \param actions
    *   The action(s) to perform for this rule.
    */
    explicit SetPushRuleActionsJob(std::string serverUrl
    , std::string _accessToken
      ,
        std::string scope , std::string kind , std::string ruleId , immer::array<Variant> actions 
        );
    

    static BaseJob::Query buildQuery(
    );

      static BaseJob::Body buildBody(std::string scope, std::string kind, std::string ruleId, immer::array<Variant> actions);

        

        

      SetPushRuleActionsJob withData(JsonWrap j) &&;
      SetPushRuleActionsJob withData(JsonWrap j) const &;
      };
      using SetPushRuleActionsResponse = SetPushRuleActionsJob::JobResponse;
      } 
      namespace nlohmann
      {
      using namespace Kazv;
      using namespace Kazv::Api;
    
    }

    namespace Kazv::Api
    {

} // namespace Kazv::Api
