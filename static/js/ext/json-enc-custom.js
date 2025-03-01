(function () {
  let api;
  htmx.defineExtension('json-enc-custom', {
      init: function (apiRef) {
          api = apiRef
      },
      onEvent: function (name, evt) {
          if (name === "htmx:configRequest") {
              evt.detail.headers['Content-Type'] = "application/json";
          }
      },
      encodeParameters: function (xhr, parameters, elt) {
          xhr.overrideMimeType('text/json');

          let encoded_parameters = encodingAlgorithm(parameters, elt);

          return encoded_parameters;
      }
  });

  function encodingAlgorithm(parameters, elt, includedElt) {
      let resultingObject = Object.create(null);
      const PARAM_NAMES = Object.keys(parameters);
      const PARAM_VALUES = Object.values(parameters);
      const PARAM_LENGTH = PARAM_NAMES.length;

      for (let param_index = 0; param_index < PARAM_LENGTH; param_index++) {
          let name = PARAM_NAMES[param_index];
          let value = PARAM_VALUES[param_index];

          let parse_value = api.getAttributeValue(elt, "parse-types");
          if (parse_value === "true" ) {
              let includedElt = getIncludedElement(elt);
              value = parseValues(elt, includedElt, name, value);
          }

          let steps = JSONEncodingPath(name);
          let context = resultingObject;

          for (let step_index = 0; step_index < steps.length; step_index++) {
              let step = steps[step_index];
              context = setValueFromPath(context, step, value);
          }
      }

      let result = JSON.stringify(resultingObject);
      return result
  }

  function parseValues(elt, includedElt, name, value) {
      let match = `[name="${name}"]`;

      let elements = elt.closest('form').querySelectorAll(match); // find the closest owning form and use this as the root element for finding matches

      if (!elements.length && includedElt !== undefined) {
          // "hx-include" allows CSS query selectors which may return an specific node, e.g a single input
          if (includedElt.matches(match)) {
              elements = [includedElt]
          } else {
              elements = includedElt.querySelectorAll(match);
          }
      }

      if (!Array.isArray(value)) return parseElementValue(elements[0], value);
      
      for (let index = 0; index < value.length; index++) {
          let array_elt = elements[index];
          let array_value = value[index];
          value[index] = parseElementValue(array_elt, array_value);
      }
      return value;
  }

  function parseElementValue(elt, value) {
      if (elt) {
          if (elt.type === "checkbox") {
              return elt.checked;
          }
          if (elt.type === "number" || elt.type === "range") {
              return Number(value);
          }
          if (elt.type === "select-one" || elt.type === "select-multiple") {
              // Проверяем, является ли значение числом
              if (!isNaN(value) && value !== "" && /^\d+$/.test(value)) {
                  return Number(value);
              }
              // Если это не число, возвращаем строку как есть
              return value;
          }
      }
      return value;
  }

  function JSONEncodingPath(name) {
      let path = name;
      let original = path;
      const FAILURE = [{ "type": "object", "key": original, "last": true, "next_type": null }];
      let steps = Array();
      let first_key = String();
      for (let i = 0; i < path.length; i++) {
          if (path[i] !== "[") first_key += path[i];
          else break;
      }
      if (first_key === "") return FAILURE;
      path = path.slice(first_key.length);
      steps.push({ "type": "object", "key": first_key, "last": false, "next_type": null });
      while (path.length) {
          // [123...]
          if (/^\[\d+\]/.test(path)) {
              path = path.slice(1);
              let collected_digits = path.match(/\d+/)[0]
              path = path.slice(collected_digits.length);
              let numeric_key = parseInt(collected_digits, 10);
              path = path.slice(1);
              steps.push({ "type": "array", "key": numeric_key, "last": false, "next_type": null });
              continue
          }
          // [abc...]
          if (/^\[[^\]]+\]/.test(path)) {
              path = path.slice(1);
              let collected_characters = path.match(/[^\]]+/)[0];
              path = path.slice(collected_characters.length);
              let object_key = collected_characters;
              path = path.slice(1);
              steps.push({ "type": "object", "key": object_key, "last": false, "next_type": null });
              continue;
          }
          return FAILURE;
      }
      for (let step_index = 0; step_index < steps.length; step_index++) {
          if (step_index === steps.length - 1) {
              let tmp_step = steps[step_index];
              tmp_step["last"] = true;
              steps[step_index] = tmp_step;
          }
          else {
              let tmp_step = steps[step_index];
              tmp_step["next_type"] = steps[step_index + 1]["type"];
              steps[step_index] = tmp_step;
          }
      }
      return steps;
  }

  function setValueFromPath(context, step, value) {
      if (step.last) {
          context[step.key] = value;
      }

      //TODO: make merge functionality and file suport.

      //check if the context value already exists
      if (context[step.key] === undefined) {
          if (step.type === "object") {
              if (step.next_type === "object") {
                  context[step.key] = {};
                  return context[step.key];
              }
              if (step.next_type === "array") {
                  context[step.key] = [];
                  return context[step.key];
              }
          }
          if (step.type === "array") {
              if (step.next_type === "object") {
                  context[step.key] = {};
                  return context[step.key];
              }
              if (step.next_type === "array") {
                  context[step.key] = [];
                  return context[step.key];
              }
          }
      }
      else {
          return context[step.key];
      }
  }

  function getIncludedElement(elt) {
      let includedSelector = api.getClosestAttributeValue(elt, "hx-include");

      if (includedSelector) {
          // "hx-include" can be inherited so `elt` will not always be the root element
          let eltWithInclude = api.getClosestMatch(elt, function(e) {
            return e.matches(`[hx-include="${includedSelector}"]`);
          })

          return api.querySelectorExt(eltWithInclude, includedSelector)
      }
  }
})()