"""The swarm on Claude (Haiku 5.5, a Sonnet 5.5 builder) follows the phase effort ladder. No model or provider is executed."""
import pathlib, sys, unittest
sys.path.insert(0,str(pathlib.Path(__file__).parent))
from sbgk_bench import pilot_ac as P
from sbgk_bench.phase_effort import EffortPolicy,parse_phase_effort

class ClaudeSwarm(unittest.TestCase):
 def test_claude_models_take_the_phase_effort_ladder(self):
  policy=EffortPolicy(parse_phase_effort("READ=medium,BUILD=low,VERIFY=medium,ANSWER=medium"),None,failure_ladder=True)
  haiku,sonnet=P.make_model("haiku"),P.make_model("sonnet");ctx={"card_id":"c1"}
  chosen,meta=policy.select(haiku,"C","BUILD",1,ctx,900)
  self.assertEqual((chosen.name,chosen.effort,chosen.timeout_s),(P.CLAUDE_HAIKU,"low",haiku.timeout_s))
  self.assertEqual(meta["model_family"],"claude:"+P.CLAUDE_HAIKU)
  policy.change("C","BUILD",1,ctx,"kernel_repair")
  self.assertEqual(policy.select(haiku,"C","BUILD",1,ctx,900)[0].effort,"medium")
  policy.change("C","BUILD",1,ctx,"timeout")
  self.assertEqual(policy.select(haiku,"C","BUILD",1,ctx,900)[0].effort,"low")
  chosen,_=policy.select(sonnet,"C","SUMMARIZE",1,{"key":"rq:RQ1"},900)
  self.assertEqual((chosen.name,chosen.effort,chosen.timeout_s),(P.CLAUDE_MODEL,"medium",900))

if __name__=="__main__":
 unittest.main()
