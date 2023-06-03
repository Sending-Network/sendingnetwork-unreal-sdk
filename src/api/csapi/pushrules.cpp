/******************************************************************************
 * THIS FILE IS GENERATED - ANY EDITS WILL BE OVERWRITTEN
 */

#include <algorithm>

#include "pushrules.hpp"

namespace Kazv::Api
{

  
BaseJob::Query GetPushRulesJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetPushRulesJob::buildBody()
      {
      // ignore unused param
      
      
      
              return BaseJob::EmptyBody{};

      };

      

GetPushRulesJob::GetPushRulesJob(
        std::string serverUrl
        , std::string _accessToken
            
        
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/pushrules",
          GET,
          std::string("GetPushRules"),
          _accessToken,
          ReturnType::Json,
            buildBody()
              , buildQuery()
                , {}

)
        {
        }

        GetPushRulesJob GetPushRulesJob::withData(JsonWrap j) &&
        {
          auto ret = GetPushRulesJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetPushRulesJob GetPushRulesJob::withData(JsonWrap j) const &
        {
          auto ret = GetPushRulesJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetPushRulesJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetPushRulesResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
            && jsonBody().get().contains("global"s)
          ;
          }


    
    PushRuleset GetPushRulesResponse::global() const
    {
    if (jsonBody().get()
    .contains("global"s)) {
    return
    jsonBody().get()["global"s]
    .template get<PushRuleset>();}
    else { return PushRuleset(  );}
    }


  
BaseJob::Query GetPushRuleJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetPushRuleJob::buildBody(std::string scope, std::string kind, std::string ruleId)
      {
      // ignore unused param
      (void)(scope);(void)(kind);(void)(ruleId);
      
      
              return BaseJob::EmptyBody{};

      };

      

GetPushRuleJob::GetPushRuleJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string scope, std::string kind, std::string ruleId
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/pushrules/" + scope + "/" + kind + "/" + ruleId,
          GET,
          std::string("GetPushRule"),
          _accessToken,
          ReturnType::Json,
            buildBody(scope, kind, ruleId)
              , buildQuery()
                , {}

)
        {
        }

        GetPushRuleJob GetPushRuleJob::withData(JsonWrap j) &&
        {
          auto ret = GetPushRuleJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetPushRuleJob GetPushRuleJob::withData(JsonWrap j) const &
        {
          auto ret = GetPushRuleJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetPushRuleJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetPushRuleResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query DeletePushRuleJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body DeletePushRuleJob::buildBody(std::string scope, std::string kind, std::string ruleId)
      {
      // ignore unused param
      (void)(scope);(void)(kind);(void)(ruleId);
      
      
              return BaseJob::EmptyBody{};

      };

      

DeletePushRuleJob::DeletePushRuleJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string scope, std::string kind, std::string ruleId
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/pushrules/" + scope + "/" + kind + "/" + ruleId,
          DELETE,
          std::string("DeletePushRule"),
          _accessToken,
          ReturnType::Json,
            buildBody(scope, kind, ruleId)
              , buildQuery()
                , {}

)
        {
        }

        DeletePushRuleJob DeletePushRuleJob::withData(JsonWrap j) &&
        {
          auto ret = DeletePushRuleJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        DeletePushRuleJob DeletePushRuleJob::withData(JsonWrap j) const &
        {
          auto ret = DeletePushRuleJob(*this);
          ret.attachData(j);
          return ret;
        }

        DeletePushRuleJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool DeletePushRuleResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query SetPushRuleJob::buildQuery(
std::optional<std::string> before, std::optional<std::string> after)
{
BaseJob::Query _q;
  
    addToQueryIfNeeded(_q, "before"s, before);
  
    addToQueryIfNeeded(_q, "after"s, after);
return _q;
}

    BaseJob::Body SetPushRuleJob::buildBody(std::string scope, std::string kind, std::string ruleId, immer::array<Variant> actions, std::optional<std::string> before, std::optional<std::string> after, immer::array<PushCondition> conditions, std::optional<std::string> pattern)
      {
      // ignore unused param
      (void)(scope);(void)(kind);(void)(ruleId);(void)(actions);(void)(before);(void)(after);(void)(conditions);(void)(pattern);
      
        json _data
        ;
        
            _data["actions"s] = actions;
          
          
            addToJsonIfNeeded(_data, "conditions"s, conditions);
          
            addToJsonIfNeeded(_data, "pattern"s, pattern);
        return BaseJob::JsonBody(_data);
        

      };

      

SetPushRuleJob::SetPushRuleJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string scope, std::string kind, std::string ruleId, immer::array<Variant> actions, std::optional<std::string> before, std::optional<std::string> after, immer::array<PushCondition> conditions, std::optional<std::string> pattern
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/pushrules/" + scope + "/" + kind + "/" + ruleId,
          PUT,
          std::string("SetPushRule"),
          _accessToken,
          ReturnType::Json,
            buildBody(scope, kind, ruleId, actions, before, after, conditions, pattern)
              , buildQuery(before, after)
                , {}

)
        {
        }

        SetPushRuleJob SetPushRuleJob::withData(JsonWrap j) &&
        {
          auto ret = SetPushRuleJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        SetPushRuleJob SetPushRuleJob::withData(JsonWrap j) const &
        {
          auto ret = SetPushRuleJob(*this);
          ret.attachData(j);
          return ret;
        }

        SetPushRuleJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool SetPushRuleResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query IsPushRuleEnabledJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body IsPushRuleEnabledJob::buildBody(std::string scope, std::string kind, std::string ruleId)
      {
      // ignore unused param
      (void)(scope);(void)(kind);(void)(ruleId);
      
      
              return BaseJob::EmptyBody{};

      };

      

IsPushRuleEnabledJob::IsPushRuleEnabledJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string scope, std::string kind, std::string ruleId
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/pushrules/" + scope + "/" + kind + "/" + ruleId + "/enabled",
          GET,
          std::string("IsPushRuleEnabled"),
          _accessToken,
          ReturnType::Json,
            buildBody(scope, kind, ruleId)
              , buildQuery()
                , {}

)
        {
        }

        IsPushRuleEnabledJob IsPushRuleEnabledJob::withData(JsonWrap j) &&
        {
          auto ret = IsPushRuleEnabledJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        IsPushRuleEnabledJob IsPushRuleEnabledJob::withData(JsonWrap j) const &
        {
          auto ret = IsPushRuleEnabledJob(*this);
          ret.attachData(j);
          return ret;
        }

        IsPushRuleEnabledJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool IsPushRuleEnabledResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
            && jsonBody().get().contains("enabled"s)
          ;
          }


    
    bool IsPushRuleEnabledResponse::enabled() const
    {
    if (jsonBody().get()
    .contains("enabled"s)) {
    return
    jsonBody().get()["enabled"s]
    .template get<bool>();}
    else { return bool(  );}
    }


  
BaseJob::Query SetPushRuleEnabledJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body SetPushRuleEnabledJob::buildBody(std::string scope, std::string kind, std::string ruleId, bool enabled)
      {
      // ignore unused param
      (void)(scope);(void)(kind);(void)(ruleId);(void)(enabled);
      
        json _data
        ;
        
            _data["enabled"s] = enabled;
          
        return BaseJob::JsonBody(_data);
        

      };

      

SetPushRuleEnabledJob::SetPushRuleEnabledJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string scope, std::string kind, std::string ruleId, bool enabled
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/pushrules/" + scope + "/" + kind + "/" + ruleId + "/enabled",
          PUT,
          std::string("SetPushRuleEnabled"),
          _accessToken,
          ReturnType::Json,
            buildBody(scope, kind, ruleId, enabled)
              , buildQuery()
                , {}

)
        {
        }

        SetPushRuleEnabledJob SetPushRuleEnabledJob::withData(JsonWrap j) &&
        {
          auto ret = SetPushRuleEnabledJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        SetPushRuleEnabledJob SetPushRuleEnabledJob::withData(JsonWrap j) const &
        {
          auto ret = SetPushRuleEnabledJob(*this);
          ret.attachData(j);
          return ret;
        }

        SetPushRuleEnabledJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool SetPushRuleEnabledResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }



  
BaseJob::Query GetPushRuleActionsJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body GetPushRuleActionsJob::buildBody(std::string scope, std::string kind, std::string ruleId)
      {
      // ignore unused param
      (void)(scope);(void)(kind);(void)(ruleId);
      
      
              return BaseJob::EmptyBody{};

      };

      

GetPushRuleActionsJob::GetPushRuleActionsJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string scope, std::string kind, std::string ruleId
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/pushrules/" + scope + "/" + kind + "/" + ruleId + "/actions",
          GET,
          std::string("GetPushRuleActions"),
          _accessToken,
          ReturnType::Json,
            buildBody(scope, kind, ruleId)
              , buildQuery()
                , {}

)
        {
        }

        GetPushRuleActionsJob GetPushRuleActionsJob::withData(JsonWrap j) &&
        {
          auto ret = GetPushRuleActionsJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        GetPushRuleActionsJob GetPushRuleActionsJob::withData(JsonWrap j) const &
        {
          auto ret = GetPushRuleActionsJob(*this);
          ret.attachData(j);
          return ret;
        }

        GetPushRuleActionsJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool GetPushRuleActionsResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
            && jsonBody().get().contains("actions"s)
          ;
          }


    
    immer::array<Variant> GetPushRuleActionsResponse::actions() const
    {
    if (jsonBody().get()
    .contains("actions"s)) {
    return
    jsonBody().get()["actions"s]
    .template get<immer::array<Variant>>();}
    else { return immer::array<Variant>(  );}
    }


  
BaseJob::Query SetPushRuleActionsJob::buildQuery(
)
{
BaseJob::Query _q;

return _q;
}

    BaseJob::Body SetPushRuleActionsJob::buildBody(std::string scope, std::string kind, std::string ruleId, immer::array<Variant> actions)
      {
      // ignore unused param
      (void)(scope);(void)(kind);(void)(ruleId);(void)(actions);
      
        json _data
        ;
        
            _data["actions"s] = actions;
          
        return BaseJob::JsonBody(_data);
        

      };

      

SetPushRuleActionsJob::SetPushRuleActionsJob(
        std::string serverUrl
        , std::string _accessToken
            ,
        std::string scope, std::string kind, std::string ruleId, immer::array<Variant> actions
        )
      : BaseJob(std::move(serverUrl),
          std::string("/_api/client/r0") + "/pushrules/" + scope + "/" + kind + "/" + ruleId + "/actions",
          PUT,
          std::string("SetPushRuleActions"),
          _accessToken,
          ReturnType::Json,
            buildBody(scope, kind, ruleId, actions)
              , buildQuery()
                , {}

)
        {
        }

        SetPushRuleActionsJob SetPushRuleActionsJob::withData(JsonWrap j) &&
        {
          auto ret = SetPushRuleActionsJob(std::move(*this));
          ret.attachData(j);
          return ret;
        }

        SetPushRuleActionsJob SetPushRuleActionsJob::withData(JsonWrap j) const &
        {
          auto ret = SetPushRuleActionsJob(*this);
          ret.attachData(j);
          return ret;
        }

        SetPushRuleActionsJob::JobResponse::JobResponse(Response r)
        : Response(std::move(r)) {}

          bool SetPushRuleActionsResponse::success() const
          {
            return Response::success()
            
              && isBodyJson(body)
          ;
          }


}
