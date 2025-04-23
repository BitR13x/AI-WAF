import re
from transformers import DistilBertTokenizer, DistilBertForSequenceClassification
from transformers import logging as hf_logging
import torch
import logging
from utils import relative_path
import os


class AIBased:
    def __init__(self, MODEL_NAME, trained_model_paths: list[str, str], LABELS: list[dict, dict],
     device: torch.device = torch.device("cpu"), probability_catch: float = 0.9):
        self.url_labels, self.data_labels = LABELS
        self.probability_catch = probability_catch
        self.tokenizer = DistilBertTokenizer.from_pretrained(MODEL_NAME)
        self.device = device

        hf_logging.set_verbosity_error()

        # AI init
        self.url_model = DistilBertForSequenceClassification.from_pretrained(
            MODEL_NAME, num_labels=len(self.url_labels)
        ).to(self.device)

        self.data_model = DistilBertForSequenceClassification.from_pretrained(
            MODEL_NAME, num_labels=len(self.data_labels)
        ).to(self.device)

        # weights_only=True: use only for trusted sources
        self.url_model.load_state_dict(
            torch.load(trained_model_paths[0], weights_only=False, map_location=torch.device("cpu"))
        )

        self.data_model.load_state_dict(
            torch.load(trained_model_paths[1], weights_only=False, map_location=torch.device("cpu"))
        )

        self.url_model.eval()
        self.data_model.eval()


    def verify_data(self, post_body) -> bool:
        if post_body:
            inputs = self.tokenizer(
                post_body,
                truncation=True,
                padding=True,
                return_tensors="pt",
                max_length=500
            ).to(self.device)

            with torch.no_grad():
                outputs = self.data_model(**inputs)

            probabilities = torch.nn.functional.softmax(outputs.logits, dim=-1)
            predicted_class_index = torch.argmax(probabilities, dim=-1).item()

            predicted_class_name = self.data_labels[predicted_class_index]

            logging.info(f"The predicted class for the text is: {predicted_class_name}")
            logging.info(f"Probabilities for each class: {probabilities.numpy()}")

            if max(probabilities[0]) < self.probability_catch:
                return True
            else:
                return False

        return True

    def verify_url(self, url: str) -> bool:
        inputs = self.tokenizer(url,
            truncation=True,
            padding=True,
            return_tensors="pt",
            max_length=500
        ).to(self.device)

        with torch.no_grad():
            outputs = self.url_model(**inputs)

        probabilities = torch.nn.functional.softmax(outputs.logits, dim=-1)
        predicted_class_index = torch.argmax(probabilities, dim=-1).item()

        predicted_class_name = self.url_labels[predicted_class_index]
        logging.info(f"Probabilities for each class: {probabilities.numpy()}: {predicted_class_name}")

        if max(probabilities[0]) < self.probability_catch:
            # We are not that certain
            return True

        if predicted_class_name == "goodqueries":
            return True
        else:
            return False




class SignatureBased:
    def __init__(self, signatures_paths: dict):
        self.signatures_paths = signatures_paths

        check_variables = ["url", "agents", "errors", "body"]
        for var in check_variables:
            if self.signatures_paths[var] == None:
                raise IndexError(f"'{var}' not in signatures_paths")

    def __get_files_in_dir(self, dir_path: str) -> list:
        if os.path.isdir(dir_path):
            return os.listdir(dir_path)
        else:
            return []

    def __search_string_in_file(self, file_path: str, string: str) -> bool:        
        with open(file_path, "r") as f:
            for line in f:
                # empty line or comment
                if line[0] == "#" or line[0] == "\n":
                    continue
                
                # remove newline
                if line[-1]:
                    line = line[:-1]

                if re.search(re.escape(line), string):
                    return True # packet dangerous

        return False

    def __verify_signature(self, string: str, var: str) -> bool:
        files = self.__get_files_in_dir(self.signatures_paths[var])
        if len(files) > 0:
            for file in files:
                file_path = os.path.join(relative_path(self.signatures_paths[var]), file)
                if self.__search_string_in_file(file_path, string):
                    return False
        
        # returning True if path does not exist!
        return True


    def verify_url(self, url: str) -> bool:
        # SSRF, restricted files, LFI
        return self.__verify_signature(url, "url")


    def verify_agent(self, headers: dict) -> bool:
        # Bots
        for header in headers:
            if header.lower() == "user-agent":
                return self.__verify_signature(headers[header], "agents")
        # missing user-agent
        return False


    def verify_response(self, response_text: str) -> bool:
        # errors in response
        return self.__verify_signature(response_text, "errors")

    def verify_data(self, post_body: str) -> bool:
        # functions in payload
        return self.__verify_signature(post_body, "body")


#? CRS_HEADER = 'X-CRS-Test'
#? possible upgrade using header,  client <!- proxy <- server