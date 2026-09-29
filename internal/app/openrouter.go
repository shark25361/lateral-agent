package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"iter"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"google.golang.org/adk/v2/model"
	"google.golang.org/genai"
)

type OpenRouter struct {
	Key, Model, Base string
	HTTP             *http.Client
}
type budgetKey struct{}

func modelBudget(ctx context.Context) context.Context {
	return context.WithValue(ctx, budgetKey{}, new(atomic.Int32))
}
func (m *OpenRouter) Name() string { return m.Model }
func schemaValue(v any) any {
	b, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(b, &out)
	return normalizeSchema(out)
}
func normalizeSchema(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, y := range x {
			if k == "type" {
				if t, ok := y.(string); ok {
					x[k] = strings.ToLower(t)
					continue
				}
			}
			x[k] = normalizeSchema(y)
		}
	case []any:
		for i, y := range x {
			x[i] = normalizeSchema(y)
		}
	}
	return v
}
func (m *OpenRouter) GenerateContent(ctx context.Context, req *model.LLMRequest, stream bool) iter.Seq2[*model.LLMResponse, error] {
	return func(yield func(*model.LLMResponse, error) bool) {
		if req == nil {
			yield(nil, fmt.Errorf("empty model request"))
			return
		}
		if b, ok := ctx.Value(budgetKey{}).(*atomic.Int32); ok && b.Add(1) > 12 {
			yield(nil, fmt.Errorf("model turn exceeded 12 calls; narrow the request"))
			return
		}
		messages := []map[string]any{}
		if req.Config != nil && req.Config.SystemInstruction != nil {
			var text strings.Builder
			for _, p := range req.Config.SystemInstruction.Parts {
				text.WriteString(p.Text)
			}
			messages = append(messages, map[string]any{"role": "system", "content": text.String()})
		}
		for _, c := range req.Contents {
			role := c.Role
			if role == "model" {
				role = "assistant"
			}
			var text strings.Builder
			calls := []map[string]any{}
			results := []map[string]any{}
			for _, p := range c.Parts {
				if p.Thought {
					continue
				}
				text.WriteString(p.Text)
				if fc := p.FunctionCall; fc != nil {
					b, e := json.Marshal(fc.Args)
					if e != nil {
						yield(nil, e)
						return
					}
					if fc.ID == "" {
						yield(nil, fmt.Errorf("tool call missing correlation ID"))
						return
					}
					calls = append(calls, map[string]any{"id": fc.ID, "type": "function", "function": map[string]any{"name": fc.Name, "arguments": string(b)}})
				}
				if fr := p.FunctionResponse; fr != nil {
					b, e := json.Marshal(fr.Response)
					if e != nil {
						yield(nil, e)
						return
					}
					if fr.ID == "" {
						yield(nil, fmt.Errorf("tool result missing correlation ID"))
						return
					}
					results = append(results, map[string]any{"role": "tool", "tool_call_id": fr.ID, "content": string(b)})
				}
			}
			if text.Len() > 0 || len(calls) > 0 {
				msg := map[string]any{"role": role, "content": text.String()}
				if len(calls) > 0 {
					msg["tool_calls"] = calls
				}
				messages = append(messages, msg)
			}
			messages = append(messages, results...)
		}
		body := map[string]any{"model": m.Model, "messages": messages, "stream": false, "max_tokens": 16384, "provider": map[string]any{"require_parameters": true}}
		declarations := []map[string]any{}
		if req.Config != nil {
			for _, t := range req.Config.Tools {
				for _, d := range t.FunctionDeclarations {
					var params any = map[string]any{"type": "object", "properties": map[string]any{}}
					if d.ParametersJsonSchema != nil {
						params = schemaValue(d.ParametersJsonSchema)
					} else if d.Parameters != nil {
						params = schemaValue(d.Parameters)
					}
					declarations = append(declarations, map[string]any{"type": "function", "function": map[string]any{"name": d.Name, "description": d.Description, "parameters": params}})
				}
			}
		}
		if len(declarations) > 0 {
			body["tools"] = declarations
			body["tool_choice"] = "auto"
		}
		raw, e := json.Marshal(body)
		if e != nil {
			yield(nil, e)
			return
		}
		if len(raw) > 400000 {
			yield(nil, fmt.Errorf("conversation context too large; start a new session"))
			return
		}
		r, e := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(m.Base, "/")+"/chat/completions", bytes.NewReader(raw))
		if e != nil {
			yield(nil, e)
			return
		}
		r.Header.Set("Authorization", "Bearer "+m.Key)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-OpenRouter-Title", "FourCore ADK Agent")
		client := m.HTTP
		if client == nil {
			client = &http.Client{Timeout: 90 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
		}
		resp, e := client.Do(r)
		if e != nil {
			yield(nil, fmt.Errorf("OpenRouter request failed: %w", e))
			return
		}
		defer resp.Body.Close()
		raw, e = io.ReadAll(io.LimitReader(resp.Body, 2<<20+1))
		if e != nil {
			yield(nil, e)
			return
		}
		if len(raw) > 2<<20 {
			yield(nil, fmt.Errorf("model response exceeds limit"))
			return
		}
		if resp.StatusCode != 200 {
			yield(nil, fmt.Errorf("OpenRouter HTTP %d; check model, credits and provider capabilities", resp.StatusCode))
			return
		}
		var result struct {
			Choices []struct {
				Finish  string `json:"finish_reason"`
				Message struct {
					Content string `json:"content"`
					Calls   []struct {
						ID       string `json:"id"`
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls"`
				} `json:"message"`
			} `json:"choices"`
			Usage struct {
				Prompt     int32 `json:"prompt_tokens"`
				Completion int32 `json:"completion_tokens"`
				Total      int32 `json:"total_tokens"`
			} `json:"usage"`
		}
		if e = json.Unmarshal(raw, &result); e != nil {
			yield(nil, fmt.Errorf("invalid OpenRouter response"))
			return
		}
		if len(result.Choices) == 0 {
			yield(nil, fmt.Errorf("OpenRouter returned no choice"))
			return
		}
		ch := result.Choices[0]
		if ch.Finish != "stop" && ch.Finish != "tool_calls" {
			yield(nil, fmt.Errorf("model response incomplete: %s", ch.Finish))
			return
		}
		content := &genai.Content{Role: "model"}
		if ch.Message.Content != "" {
			content.Parts = append(content.Parts, &genai.Part{Text: ch.Message.Content})
		}
		seen := map[string]bool{}
		for _, c := range ch.Message.Calls {
			if c.ID == "" || seen[c.ID] {
				yield(nil, fmt.Errorf("invalid tool call ID"))
				return
			}
			seen[c.ID] = true
			var args map[string]any
			if e = json.Unmarshal([]byte(c.Function.Arguments), &args); e != nil || args == nil {
				yield(nil, fmt.Errorf("invalid tool arguments"))
				return
			}
			content.Parts = append(content.Parts, &genai.Part{FunctionCall: &genai.FunctionCall{ID: c.ID, Name: c.Function.Name, Args: args}})
		}
		if len(content.Parts) == 0 {
			yield(nil, fmt.Errorf("empty model answer"))
			return
		}
		yield(&model.LLMResponse{Content: content, TurnComplete: true, UsageMetadata: &genai.GenerateContentResponseUsageMetadata{PromptTokenCount: result.Usage.Prompt, CandidatesTokenCount: result.Usage.Completion, TotalTokenCount: result.Usage.Total}}, nil)
	}
}
