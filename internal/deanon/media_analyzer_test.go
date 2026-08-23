package deanon

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	exif "github.com/dsoprea/go-exif/v3"
	exifcommon "github.com/dsoprea/go-exif/v3/common"

	"github.com/nao1215/onionscan/internal/model"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }
func (failingReader) Close() error             { return nil }

func responseClient(contentType string, contentLength int64, body io.ReadCloser) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode:    http.StatusOK,
			Header:        http.Header{"Content-Type": []string{contentType}},
			ContentLength: contentLength,
			Body:          body,
		}, nil
	})}
}

func buildTestEXIF(t *testing.T) []byte {
	t.Helper()

	ifdMapping, err := exifcommon.NewIfdMappingWithStandard()
	if err != nil {
		t.Fatalf("create EXIF mapping: %v", err)
	}
	root := exif.NewIfdBuilder(
		ifdMapping,
		exif.NewTagIndex(),
		exifcommon.IfdStandardIfdIdentity,
		binary.LittleEndian,
	)
	for tag, value := range map[string]string{
		"Make":               "Onion Camera",
		"Model":              "Model 7",
		"Software":           "Onion Editor",
		"ProcessingSoftware": "Onion Processor",
		"Artist":             "Alice Operator",
		"Copyright":          "Alice Copyright",
		"DateTime":           "2026:08:23 12:34:56",
		"HostComputer":       "onion-workstation",
	} {
		if err := root.SetStandardWithName(tag, value); err != nil {
			t.Fatalf("set EXIF tag %s: %v", tag, err)
		}
	}

	encoded, err := exif.NewIfdByteEncoder().EncodeToExif(root)
	if err != nil {
		t.Fatalf("encode EXIF: %v", err)
	}
	return encoded
}

func TestEXIFAnalyzerImagePaths(t *testing.T) {
	t.Parallel()

	exifData := buildTestEXIF(t)

	t.Run("extracts findings from inline EXIF", func(t *testing.T) {
		t.Parallel()

		analyzer := NewEXIFAnalyzer()
		dataURL := "data:image/jpeg;base64," + base64.StdEncoding.EncodeToString(exifData)
		findings := analyzer.analyzeImage(context.Background(), dataURL, "http://test.onion/")
		if len(findings) < 6 {
			t.Fatalf("expected EXIF findings, got %d", len(findings))
		}
		findingTypes := make(map[string]bool)
		for _, finding := range findings {
			findingTypes[finding.Type] = true
		}
		for _, findingType := range []string{"exif_camera", "exif_software", "exif_author", "exif_datetime", "exif_computer"} {
			if !findingTypes[findingType] {
				t.Errorf("missing %s finding", findingType)
			}
		}
	})

	t.Run("fetches same-origin image", func(t *testing.T) {
		t.Parallel()

		analyzer := NewEXIFAnalyzer()
		analyzer.targetHost = "test.onion"
		analyzer.SetHTTPClient(responseClient("image/jpeg", int64(len(exifData)), io.NopCloser(bytes.NewReader(exifData))))
		findings := analyzer.analyzeImage(
			context.Background(),
			"http://test.onion/photo.jpg",
			"http://test.onion/",
		)
		if len(findings) == 0 {
			t.Fatal("expected findings from fetched EXIF image")
		}
	})

	t.Run("analyzes and deduplicates page images", func(t *testing.T) {
		t.Parallel()

		analyzer := NewEXIFAnalyzer()
		analyzer.SetHTTPClient(responseClient("image/jpeg", int64(len(exifData)), io.NopCloser(bytes.NewReader(exifData))))
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{
				{
					URL: "http://test.onion/",
					Images: []model.Element{
						{Source: "http://test.onion/photo.jpg"},
						{Source: "http://test.onion/photo.jpg"},
						{Source: "http://test.onion/logo.png"},
						{},
					},
					Snapshot: `<img src="http://test.onion/photo.jpg"><img src="http://test.onion/logo.png">`,
				},
			},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil || len(findings) == 0 {
			t.Fatalf("Analyze() findings=%d err=%v", len(findings), err)
		}
		if analyzer.targetHost != "test.onion" {
			t.Fatalf("target host = %q", analyzer.targetHost)
		}
	})

	t.Run("requires client and respects cancellation", func(t *testing.T) {
		t.Parallel()

		analyzer := NewEXIFAnalyzer()
		if _, err := analyzer.Analyze(context.Background(), &AnalysisData{}); !errors.Is(err, ErrNoHTTPClient) {
			t.Fatalf("expected ErrNoHTTPClient, got %v", err)
		}
		analyzer.SetHTTPClient(http.DefaultClient)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := analyzer.Analyze(ctx, &AnalysisData{Pages: []*model.Page{{}}}); !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context cancellation, got %v", err)
		}
		analyzer.targetHost = "test.onion"
		analyzer.SetAllowExternalFetch(true)
		if !analyzer.isAllowedURL("http://other.onion/photo.jpg") {
			t.Fatal("external onion URL should be allowed after opt-in")
		}
		if analyzer.isAllowedURL("http://%/photo.jpg") {
			t.Fatal("malformed URL should not be allowed")
		}
	})

	t.Run("handles malformed data URLs", func(t *testing.T) {
		t.Parallel()

		analyzer := NewEXIFAnalyzer()
		for _, dataURL := range []string{
			"data:image/jpeg;base64",
			"data:image/jpeg;base64,%%%",
			"data:image/jpeg;base64," + base64.RawURLEncoding.EncodeToString([]byte("not exif")),
		} {
			if findings := analyzer.analyzeDataURL(dataURL, "http://test.onion/"); len(findings) != 0 {
				t.Errorf("expected no findings for malformed image data, got %d", len(findings))
			}
		}
	})

	t.Run("rejects unsafe and unusable image responses", func(t *testing.T) {
		t.Parallel()

		analyzer := NewEXIFAnalyzer()
		analyzer.targetHost = "test.onion"
		if findings := analyzer.analyzeImage(context.Background(), "ftp://test.onion/photo.jpg", "page"); len(findings) != 0 {
			t.Fatal("non-HTTP image was analyzed")
		}
		if findings := analyzer.analyzeImage(context.Background(), "https://example.com/photo.jpg", "page"); len(findings) != 0 {
			t.Fatal("clearnet image was analyzed")
		}
		if findings := analyzer.analyzeImage(context.Background(), "http://test.onion/photo.jpg", "page"); len(findings) != 0 {
			t.Fatal("image was fetched without an HTTP client")
		}

		analyzer.SetHTTPClient(responseClient("image/jpeg", analyzer.maxImageSize+1, io.NopCloser(strings.NewReader("oversized"))))
		if findings := analyzer.analyzeImage(context.Background(), "http://test.onion/photo.jpg", "page"); len(findings) != 0 {
			t.Fatal("oversized image was analyzed")
		}

		analyzer.SetHTTPClient(responseClient("image/jpeg", -1, failingReader{}))
		if findings := analyzer.analyzeImage(context.Background(), "http://test.onion/photo.jpg", "page"); len(findings) != 0 {
			t.Fatal("unreadable image was analyzed")
		}

		analyzer.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("fetch failed")
		})})
		if findings := analyzer.analyzeImage(context.Background(), "http://test.onion/photo.jpg", "page"); len(findings) != 0 {
			t.Fatal("failed image request produced findings")
		}
	})
}

func TestPDFAnalyzerDownloadPaths(t *testing.T) {
	t.Parallel()

	pdfContent := []byte(`%PDF-1.7
/Author (Alice Operator)
/Creator (LibreOffice)
/Producer (Onion PDF Library)
/CreationDate (D:20260823123456+09'00')
<dc:creator><rdf:li>Alice XMP</rdf:li></dc:creator>
<xmp:CreatorTool>Onion Tool</xmp:CreatorTool>
<pdf:Producer>Onion XMP Producer</pdf:Producer>
<xmpMM:DocumentID>uuid:document-123</xmpMM:DocumentID>
<xmpMM:InstanceID>uuid:instance-456</xmpMM:InstanceID>
<xmpMM:OriginalDocumentID>uuid:original-789</xmpMM:OriginalDocumentID>`)

	t.Run("downloads and analyzes same-origin PDF", func(t *testing.T) {
		t.Parallel()

		analyzer := NewPDFAnalyzer()
		analyzer.SetHTTPClient(responseClient("application/pdf", int64(len(pdfContent)), io.NopCloser(bytes.NewReader(pdfContent))))
		data := &AnalysisData{
			HiddenService: "test.onion",
			Pages: []*model.Page{{
				URL: "http://test.onion/",
				Links: []model.Element{
					{Source: "http://test.onion/document.pdf"},
					{Source: "http://test.onion/document.pdf"},
				},
			}},
		}

		findings, err := analyzer.Analyze(context.Background(), data)
		if err != nil {
			t.Fatalf("Analyze returned error: %v", err)
		}
		if len(findings) < 8 {
			t.Fatalf("expected rich PDF metadata findings, got %d", len(findings))
		}
	})

	t.Run("skips blocked and failed downloads", func(t *testing.T) {
		t.Parallel()

		analyzer := NewPDFAnalyzer()
		analyzer.targetHost = "test.onion"
		if findings := analyzer.analyzePDF(context.Background(), "https://example.com/document.pdf", "page"); len(findings) != 0 {
			t.Fatal("clearnet PDF was analyzed")
		}
		if _, err := analyzer.downloadPDF(context.Background(), "http://test.onion/document.pdf"); !errors.Is(err, ErrNoPDFHTTPClient) {
			t.Fatalf("expected ErrNoPDFHTTPClient, got %v", err)
		}

		analyzer.SetHTTPClient(responseClient("text/plain", 4, io.NopCloser(strings.NewReader("text"))))
		data, err := analyzer.downloadPDF(context.Background(), "http://test.onion/document.pdf")
		if err != nil || data != nil {
			t.Fatalf("non-PDF response = %q, %v; want nil, nil", data, err)
		}

		analyzer.SetHTTPClient(responseClient("application/octet-stream", -1, failingReader{}))
		if _, err := analyzer.downloadPDF(context.Background(), "http://test.onion/document.pdf"); err == nil {
			t.Fatal("expected unreadable PDF body error")
		}

		fetchErr := errors.New("fetch failed")
		analyzer.SetHTTPClient(&http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, fetchErr
		})})
		if _, err := analyzer.downloadPDF(context.Background(), "http://test.onion/document.pdf"); !errors.Is(err, fetchErr) {
			t.Fatalf("expected fetch error, got %v", err)
		}
		if findings := analyzer.analyzePDF(context.Background(), "http://test.onion/document.pdf", "page"); len(findings) != 0 {
			t.Fatal("failed PDF request produced findings")
		}
	})
}
