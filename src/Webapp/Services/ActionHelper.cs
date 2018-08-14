namespace Webapp.Services
{
    using System;
    using System.Text;
    using GrainInterfaces;

    internal static class ActionHelper
    {
        public static IAction ConstructTypedAction(dynamic action)
        {
            if ((action == null) || (action.type == null))
            {
                return null;
            }

            // TODO: action.type should not be trusted as it is external input; it should be validated
            // Our actions are always defined inside GrainInterfaces for now
            Type actionType = Type.GetType("GrainInterfaces." + action.type + ",GrainInterfaces");

            if (action.payload == null)
            {
                return Activator.CreateInstance(actionType) as IAction;
            }

            return (IAction) Convert.ChangeType(action.payload, actionType);
        }

        public static string ActionName(string className)
        {
            var sb = new StringBuilder();

            var name = className.Substring(0, className.Length - 6); // remove 'Action'
            var first = true;
            foreach (var c in name)
            {
                if (char.IsUpper(c) && !first)
                {
                    sb.Append("_");
                }

                sb.Append(char.ToUpper(c));
                if (first)
                {
                    first = false;
                }
            }

            return sb.ToString();
        }
    }
}